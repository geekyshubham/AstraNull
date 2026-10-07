import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { decodeCursor } from '../../src/lib/cursorPagination.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  MAX_CAPTURED_RUNS,
  MAX_DECLARED_MEMBERS,
  MAX_REPORT_SCOPE_IDS,
  MAX_SNAPSHOT_EVIDENCE,
  MAX_SNAPSHOT_FINDINGS,
} from '../../src/services/reports.mjs';

const AS_OF = '2026-10-04T00:00:00.000Z';
const RECENT = '2026-10-03T00:00:00.000Z';
const OLD = '2026-09-01T00:00:00.000Z';
const HI = '2026-10-04T12:00:00.100002Z';
const LO = '2026-10-04T12:00:00.100001Z';
const LATER = '2026-10-04T12:00:00.200000Z';
const MARKER = 'l7.waf_marker_rule.safe';
const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';

function adminHeaders(tenant = 'ten_demo') {
  return demoHeaders('admin', tenant, 'usr_admin');
}

async function get(baseUrl, path, headers = adminHeaders()) {
  const res = await request(baseUrl, 'GET', path, { headers });
  return res;
}

function assertDashboardShape(body) {
  assert.equal(body.unit, 'normalized_hostname');
  assert.equal(body.canonical_unit, 'hostname');
  assert.equal(body.denominator, body.units.normalized_hosts);
  assert.equal(typeof body.units.target_records, 'number');
  assert.equal(body.source, 'active_declared_targets');
  assert.equal(body.version, 'declared-host-analytics.v1');
  assert.equal(body.scope, 'current');
  assert.equal(body.historical, false);
  assert.equal(body.snapshot_id, null);
  assert.equal(body.as_of, AS_OF);
  assert.equal(body.as_of_semantics, 'caller_evaluation_clock');
  assert.equal(body.complete, true);
  assert.equal(body.list_query.query.unit, 'hostname');
  assert.equal(body.list_query.query.family, 'waf');
  assert.ok(Array.isArray(body.segments));
  assert.equal(body.segments.some((segment) => segment.key === 'unknown'), false);
  assert.equal(body.segments.every((segment) => typeof segment.key === 'string'), true);
  assert.equal(body.unknown_count, body.role_segments.all.waf.unknown);
  assert.equal(body.stale_count, body.role_segments.all.waf.stale);
  assert.equal(body.rollup.freshness_policy.applied, false);
  assert.equal(body.page.total, body.total);
  assert.equal(body.page.items.length, body.items.length);
}

function segmentCount(body, key) {
  return body.segments.find((segment) => segment.key === key).count;
}

describe('declared-host analytics API', () => {
  it('serves the same predicate on analytics and targets, and the exact check, compatibility, and audit reads', async () => {
    freshStore();
    const env = {
      ...process.env,
      ASTRANULL_NO_PERSIST: '1',
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
    };
    Object.assign(process.env, env);
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const store = getStore();
      const group = store.targetGroups.find((row) => row.id === 'tg_1');
      group.declaration_json = {
        criticality: 'high',
        service_roles: ['website'],
        owner_label: 'Group Owner',
      };
      store.targetVerifications = [
        {
          id: 'tv_unverified',
          tenant_id: 'ten_demo',
          target_id: 'tgt_unverified',
          state: 'unverified',
          transitioned_at: AS_OF,
        },
      ];
      store.targetEdgeDetections = [
        edge('edge_host', 'tgt_host', false, 'detected', 'not_detected', RECENT),
        edge('edge_url', 'tgt_url', false, 'detected', 'not_detected', RECENT),
        edge('edge_stale', 'tgt_stale', false, 'detected', 'not_detected', OLD),
        edge('edge_conflict', 'tgt_conflict', true, 'detected', 'not_detected', OLD),
      ];
      store.targets.push(
        target('tgt_host', 'fqdn', 'Example.com', { service_roles: ['website'], criticality: 'critical' }, { tags: ['prod'], connector_token: 'super-secret-metadata' }),
        target('tgt_url', 'url', 'https://Example.com/login', { service_roles: ['login'] }),
        target('tgt_stale', 'fqdn', 'stale.example.com', { service_roles: ['website'] }),
        target('tgt_conflict', 'fqdn', 'conflict.example.com', { service_roles: ['website'] }),
        target('tgt_ip', 'ip', '203.0.113.10', { service_roles: ['network'] }),
        target('tgt_unverified', 'fqdn', 'unverified.example.com', {}),
        target('tgt_open', 'fqdn', 'open.example.com', {}),
        target('tgt_inherit', 'fqdn', 'inherited.example.com', {}),
      );
      store.findings.push({
        id: 'f_open',
        tenant_id: 'ten_demo',
        target_id: 'tgt_open',
        target_group_id: 'tg_1',
        status: 'open',
        title: 'Open',
      });
      store.auditLog.push(
        auditRow('aud_lo', 'ten_demo', LO, 2, 'usr_admin', 'target.added', 'target', 'tgt_host'),
        auditRow('aud_hi', 'ten_demo', HI, 3, 'usr_admin', 'target.added', 'target', 'tgt_host'),
        auditRow('aud_other', 'ten_demo', LATER, 4, 'usr_other', 'target.updated', 'target_group', 'tg_1'),
        auditRow('aud_foreign', 'ten_other', HI, 1, 'usr_foreign', 'target.added', 'target', 'tgt_foreign'),
      );

      const legacy = await get(baseUrl, '/v1/targets');
      assert.equal(legacy.status, 200);
      const unverifiedItem = legacy.json.items.find((item) => item.id === 'tgt_unverified');
      assert.equal(unverifiedItem.eligibility, 'not_runnable_now');
      assert.equal(unverifiedItem.eligibility_reason, null);
      assert.deepEqual(Object.keys(legacy.json).sort(), ['count', 'items', 'meta']);
      assert.equal(legacy.json.count, legacy.json.items.length);
      assert.equal(legacy.json.count > 8, true);

      const listed = await get(baseUrl, `/v1/targets?limit=200&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(listed.status, 200, listed.text);
      assert.equal(listed.json.unit, 'target');
      assert.equal(listed.json.total, legacy.json.count);
      assert.equal(listed.json.page.total, listed.json.total);
      assert.equal(listed.json.page.items.length, legacy.json.count);
      assert.equal(listed.json.scope, 'current');
      assert.equal(listed.json.historical, false);
      assert.equal(listed.json.as_of, AS_OF);
      assert.equal(listed.text.includes('super-secret'), false);

      const coverage = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=200&as_of=${encodeURIComponent(AS_OF)}`,
      );
      assert.equal(coverage.status, 200, coverage.text);
      assertDashboardShape(coverage.json);
      assert.equal(coverage.json.units.target_records, listed.json.units.target_records);
      assert.equal(coverage.json.units.normalized_hosts, listed.json.units.normalized_hosts);
      assert.equal(coverage.json.units.normalized_hosts < coverage.json.units.target_records, true);
      assert.equal(coverage.text.includes('super-secret'), false);
      const example = coverage.json.items.find((item) => item.analytics.host_key === 'example.com');
      assert.equal(example.analytics.member_count, 2);
      assert.deepEqual(example.analytics.target_ids, ['tgt_host', 'tgt_url']);
      assert.equal(coverage.json.items.some((item) => String(item.value).includes('203.0.113.10')), false);
      assert.equal(segmentCount(coverage.json, 'not_checked') > 0, true);
      assert.equal(coverage.json.unknown_count, 0);
      assert.notEqual(coverage.json.unknown_count, segmentCount(coverage.json, 'not_checked'));

      const stale = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&family_status=stale&limit=50&as_of=${encodeURIComponent(AS_OF)}`,
      );
      assert.equal(stale.json.denominator, segmentCount(coverage.json, 'stale'));
      assert.equal(stale.json.items.some((item) => item.id === 'tgt_stale'), true);
      assert.equal(stale.json.items.some((item) => item.id === 'tgt_conflict'), false);
      const staleHost = stale.json.items.find((item) => item.id === 'tgt_stale');
      assert.equal(staleHost.protection_profile.families.waf.status, 'detected');
      assert.equal(staleHost.protection_profile.families.waf.freshness, 'stale');
      assert.equal(staleHost.analytics.families.waf.bucket, 'stale');
      assert.equal(example.protection_profile.families.waf.freshness, 'current');
      assert.equal(example.analytics.families.waf.bucket, 'detected');

      const conflict = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&family_status=conflict&unit=hostname&as_of=${encodeURIComponent(AS_OF)}`,
      );
      const conflictHost = conflict.json.items.find((item) => item.id === 'tgt_conflict');
      assert.equal(conflictHost.protection_profile.families.waf.conflict, true);
      assert.equal(conflictHost.analytics.families.waf.bucket, 'conflict');
      assert.equal(conflictHost.analytics.families.cdn.bucket, 'stale');

      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(coverage.json.list_query.query)) {
        if (['service_role', 'criticality', 'owner_status', 'tag', 'family', 'family_status', 'freshness', 'has_open_finding', 'unit'].includes(key)) {
          params.set(key, String(value));
        }
      }
      params.set('family_status', 'stale');
      params.set('limit', '200');
      params.set('as_of', AS_OF);
      const cohort = await get(baseUrl, `/v1/targets?${params.toString()}`);
      assert.equal(cohort.status, 200, cohort.text);
      assert.equal(cohort.json.page.total, stale.json.denominator);
      assert.equal(cohort.json.total, cohort.json.page.total);
      assert.equal(cohort.json.items.some((item) => item.id === 'tgt_stale'), true);

      const unknown = await get(baseUrl, `/v1/targets?verification_state=unknown&unit=hostname&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(unknown.json.items.some((item) => item.id === 'tgt_unverified'), false);
      assert.equal(unknown.json.items.some((item) => item.analytics.host_key === 'example.com'), true);
      const unverified = await get(baseUrl, `/v1/targets?verification=unverified&unit=hostname&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(unverified.json.items.some((item) => item.id === 'tgt_unverified'), true);
      assert.equal(unverified.json.items.some((item) => item.id === 'tgt_host'), false);
      const open = await get(baseUrl, `/v1/targets?has_open_finding=true&unit=target&as_of=${encodeURIComponent(AS_OF)}`);
      assert.deepEqual(open.json.items.map((item) => item.id), ['tgt_open']);

      const inherited = await get(baseUrl, `/v1/targets?q=tgt_inherit&unit=target&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(inherited.json.items[0].declaration.criticality.status, 'inherited');
      assert.equal(inherited.json.items[0].declaration.criticality.value, 'high');
      assert.equal(inherited.json.items[0].declaration.criticality.source, 'target_group');
      assert.equal(inherited.json.items[0].declaration.service_roles_status, 'inherited');
      assert.equal(inherited.json.items[0].verification_state == null, true);

      const empty = await get(baseUrl, `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&criticality=low&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(empty.json.denominator, 0);
      assert.equal(segmentCount(empty.json, 'detected'), 0);
      assert.equal(empty.json.segments.find((segment) => segment.key === 'detected').percentage, null);

      const alias = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?search=tgt_stale&group=tg_1&verification=unknown&role=website&unit=declared_target&as_of=${encodeURIComponent(AS_OF)}`,
      );
      const canonical = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?q=tgt_stale&target_group_id=tg_1&verification_state=unknown&service_role=website&unit=target&as_of=${encodeURIComponent(AS_OF)}`,
      );
      assert.equal(alias.status, 200, alias.text);
      assert.equal(alias.json.denominator, 1);
      assert.equal(alias.json.denominator, canonical.json.denominator);
      assert.equal(alias.json.canonical_unit, 'target');
      assert.equal(alias.json.unit, 'declared_target');
      assert.equal(alias.json.cohort_version, canonical.json.cohort_version);

      const badEnum = await get(baseUrl, '/v1/analytics/declared-hosts?verification_state=nope');
      assert.equal(badEnum.status, 400);
      assert.equal(badEnum.json.error, 'invalid_query_value');
      assert.equal(badEnum.json.items, undefined);
      const origin = await get(baseUrl, '/v1/targets?origin_status=exposed');
      assert.equal(origin.status, 400);
      assert.equal(origin.json.error, 'unknown_query_param');
      assert.equal((await get(baseUrl, '/v1/targets?limit=201')).status, 400);
      const clash = await get(baseUrl, '/v1/analytics/declared-hosts?search=a&q=b');
      assert.equal(clash.status, 400);
      assert.equal(clash.json.error, 'invalid_query_value');

      const page = await get(baseUrl, `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&as_of=${encodeURIComponent(AS_OF)}`);
      assert.equal(page.json.count, 1);
      assert.equal(page.json.total, coverage.json.denominator);
      const pageTwo = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&cursor=${encodeURIComponent(page.json.next_cursor)}`,
      );
      assert.equal(pageTwo.status, 200, pageTwo.text);
      assert.equal(pageTwo.json.total, page.json.total);
      assert.equal(pageTwo.json.as_of, AS_OF);
      assert.notEqual(pageTwo.json.items[0].id, page.json.items[0].id);
      const clock = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&cursor=${encodeURIComponent(page.json.next_cursor)}&as_of=${encodeURIComponent('2001-01-01T00:00:00.000Z')}`,
      );
      assert.equal(clock.status, 409);
      assert.equal(clock.json.error, 'cursor_clock_mismatch');
      assert.equal(clock.json.filters.unit, 'hostname');
      assert.equal(clock.json.total, undefined);
      const moved = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&tag=prod&cursor=${encodeURIComponent(page.json.next_cursor)}&as_of=${encodeURIComponent(AS_OF)}`,
      );
      assert.equal(moved.status, 409);
      assert.equal(moved.json.error, 'cursor_filter_mismatch');
      assert.equal(moved.json.filters.family, 'waf');

      const version = coverage.json.cohort_version;
      store.targets.push(target('tgt_url_extra', 'url', 'https://example.com/extra', { service_roles: ['website'] }));
      const changed = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&as_of=${encodeURIComponent(AS_OF)}&cohort_version=${version}`,
      );
      assert.equal(changed.status, 409);
      assert.equal(changed.json.error, 'cohort_changed');
      assert.equal(changed.json.filters.unit, 'hostname');
      assert.equal(changed.json.filters.family, 'waf');
      assert.equal(changed.json.scope, 'current');
      assert.equal(changed.json.historical, false);
      assert.equal(changed.json.total, undefined);
      assert.equal(changed.json.items, undefined);
      const refetched = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=200&as_of=${encodeURIComponent(AS_OF)}`,
      );
      assert.equal(refetched.json.denominator, coverage.json.denominator);
      assert.equal(refetched.json.units.target_records, coverage.json.units.target_records + 1);
      assert.notEqual(refetched.json.cohort_version, version);

      const runsBefore = store.testRuns.length;
      const fqdnChecks = await get(baseUrl, '/v1/targets/tgt_host/compatible-checks');
      const ipChecks = await get(baseUrl, '/v1/targets/tgt_ip/compatible-checks');
      assert.equal(fqdnChecks.status, 200, fqdnChecks.text);
      assert.equal(ipChecks.status, 200, ipChecks.text);
      assert.equal(fqdnChecks.json.runtime_launch_gates, 'not_evaluated');
      assert.equal(fqdnChecks.json.checks.every((pair) => pair.launch_block_reason === 'not_evaluated' && pair.launchable === null), true);
      assert.equal(fqdnChecks.json.checks.some((pair) => pair.check_id === MARKER), true);
      assert.equal(ipChecks.json.checks.some((pair) => pair.check_id === MARKER), false);
      assert.equal(fqdnChecks.text.includes('probe_profile'), false);
      assert.equal(store.testRuns.length, runsBefore);
      assert.equal((await get(baseUrl, '/v1/targets/missing/compatible-checks')).status, 404);
      assert.equal((await get(baseUrl, '/v1/targets/tgt_host/compatible-checks', adminHeaders('ten_other'))).status, 404);

      const exact = await get(baseUrl, `/v1/checks/${MARKER}`);
      assert.equal(exact.status, 200, exact.text);
      assert.equal(exact.json.check.check_id, MARKER);
      assert.equal(exact.json.check.version, '1.1.0');
      assert.equal(exact.json.check.supported_targets.includes('fqdn'), true);
      assert.equal(typeof exact.json.check.section_id, 'string');
      assert.equal((await get(baseUrl, '/v1/checks/missing.check.safe')).status, 404);
      assert.equal((await get(baseUrl, '/v1/checks', demoHeaders('viewer'))).status, 200);
      assert.equal((await get(baseUrl, '/v1/analytics/declared-hosts?family=waf', demoHeaders('viewer'))).status, 200);

      const added = await get(baseUrl, '/v1/audit-log?action=target.added&limit=1');
      assert.equal(added.status, 200, added.text);
      assert.equal(added.json.total, 2);
      assert.equal(added.json.count, 1);
      assert.equal(added.json.items[0].id, 'aud_hi');
      assert.equal(added.json.items.length, 1);
      const cursor = decodeCursor(added.json.next_cursor);
      assert.equal(cursor.ts, HI);
      assert.equal(cursor.ts.includes('.100002'), true);
      const older = await get(baseUrl, `/v1/audit-log?action=target.added&limit=1&cursor=${encodeURIComponent(added.json.next_cursor)}`);
      assert.equal(older.json.items[0].id, 'aud_lo');
      assert.equal(older.json.next_cursor, null);
      const precise = await get(baseUrl, `/v1/audit-log?action=target.added&since=${encodeURIComponent(HI)}&until=${encodeURIComponent(HI)}`);
      assert.deepEqual(precise.json.items.map((entry) => entry.id), ['aud_hi']);
      const actor = await get(baseUrl, '/v1/audit-log?actor=usr_other');
      assert.deepEqual(actor.json.items.map((entry) => entry.id), ['aud_other']);
      const resource = await get(baseUrl, '/v1/audit-log?resource=tg_1');
      assert.deepEqual(resource.json.items.map((entry) => entry.id), ['aud_other']);
      assert.equal((await get(baseUrl, '/v1/audit-log?since=not-a-date')).status, 400);
      const own = await get(baseUrl, '/v1/audit-log/aud_hi');
      assert.equal(own.status, 200);
      assert.equal(own.json.entry.id, 'aud_hi');
      assert.equal(own.json.entry.action, 'target.added');
      assert.equal(own.json.entry.entry_hash, 'hash-aud_hi');
      assert.equal(own.json.entry.prev_hash, 'prev-aud_hi');
      assert.deepEqual(own.json.entry.metadata, { source: 'audit_log', id: 'aud_hi' });
      const ranged = await get(baseUrl, `/v1/audit-log?action=target.added&from=${encodeURIComponent(HI)}&to=${encodeURIComponent(HI)}`);
      assert.deepEqual(ranged.json.items.map((entry) => entry.id), ['aud_hi']);
      const actorAlias = await get(baseUrl, '/v1/audit-log?actor_user_id=usr_other');
      assert.deepEqual(actorAlias.json.items.map((entry) => entry.id), ['aud_other']);
      assert.equal((await get(baseUrl, `/v1/audit-log?from=${encodeURIComponent(LO)}&since=${encodeURIComponent(HI)}`)).status, 400);
      assert.equal((await get(baseUrl, '/v1/audit-log/aud_hi', adminHeaders('ten_other'))).status, 404);
      assert.equal((await get(baseUrl, '/v1/audit-log/missing')).status, 404);
      const denied = await get(baseUrl, '/v1/audit-log', demoHeaders('viewer'));
      assert.equal(denied.status, 403);
      const still = await get(baseUrl, '/v1/audit-log?action=target.added');
      assert.equal(still.json.total, 2);
      assert.equal(still.json.items.some((entry) => entry.action === 'rbac.denied'), false);
      const recent = await get(baseUrl, '/v1/audit-log');
      assert.equal(Array.isArray(recent.json.items), true);
      assert.equal(recent.json.items.some((entry) => entry.action === 'rbac.denied'), true);
      assert.equal(recent.json.total > still.json.total, true);

      const other = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=cdn&unit=normalized_hostname&as_of=${encodeURIComponent(AS_OF)}`,
        adminHeaders('ten_other'),
      );
      assert.equal(other.status, 200, other.text);
      assert.equal(other.json.denominator, 0);
      assert.equal(other.json.historical, false);
      assert.equal(other.json.scope, 'current');
      assert.equal(other.text.includes('example.com'), false);

      store.tenants.push({ id: 'ten_wide', name: 'Wide' });
      store.targetGroups.push({ id: 'tg_wide', tenant_id: 'ten_wide', name: 'Wide' });
      for (let index = 1; index <= 5001; index += 1) {
        store.targets.push({
          id: `w${String(index).padStart(5, '0')}`,
          tenant_id: 'ten_wide',
          target_group_id: 'tg_wide',
          kind: 'fqdn',
          value: `h${index}.wide.example.com`,
        });
      }
      const wide = await get(
        baseUrl,
        '/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1',
        adminHeaders('ten_wide'),
      );
      assert.equal(wide.status, 200, wide.text);
      assert.equal(wide.json.complete, true);
      assert.equal(wide.json.denominator, 5001);
      assert.equal(wide.json.count, 1);
      assert.equal(wide.json.items.length, 1);
      assert.equal(wide.json.units.target_records, 5001);
      assert.equal(wide.json.units.normalized_hosts, 5001);
      const widePage = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&cursor=${encodeURIComponent(wide.json.next_cursor)}`,
        adminHeaders('ten_wide'),
      );
      assert.equal(widePage.json.denominator, 5001);
      assert.equal(widePage.json.items.length, 1);
      assert.notEqual(widePage.json.items[0].id, wide.json.items[0].id);
      const wideList = await get(baseUrl, '/v1/targets?limit=50', adminHeaders('ten_wide'));
      assert.equal(wideList.json.total, 5001);
      assert.equal(wideList.json.items.length, 50);
      assert.equal(wideList.json.page.count, 50);
    } finally {
      await closeServer(server);
    }
  });

  it('rejects a bad report scope before write and publishes builder capabilities', async () => {
    freshStore();
    const env = {
      ...process.env,
      ASTRANULL_NO_PERSIST: '1',
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
    };
    Object.assign(process.env, env);
    const store = getStore();
    store.tenants.push({ id: 'ten_other', name: 'Other' });
    store.targetGroups.push({ id: 'tg_other', tenant_id: 'ten_other', name: 'Other' });
    store.targets.push({
      id: 'tgt_foreign',
      tenant_id: 'ten_other',
      target_group_id: 'tg_other',
      kind: 'fqdn',
      value: 'foreign.example.com',
    });
    store.targetVerifications = [{
      id: 'tv_proven',
      tenant_id: 'ten_demo',
      target_id: 'tgt_1',
      state: 'dns_verified',
      transitioned_at: AS_OF,
    }];
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const headers = adminHeaders();
    try {
      const counts = () => ({
        reports: store.reports.length,
        audit: store.auditLog.length,
        notifications: store.notificationEvents.length,
      });
      const before = counts();
      const malformed = await request(baseUrl, 'POST', '/v1/reports', {
        headers,
        body: { target_ids: 'tgt_1' },
      });
      assert.equal(malformed.status, 400);
      assert.equal(malformed.json.error, 'invalid_scope');
      const foreign = await request(baseUrl, 'POST', '/v1/reports', {
        headers,
        body: { target_ids: ['tgt_foreign'] },
      });
      assert.equal(foreign.status, 400);
      assert.equal(foreign.json.error, 'unknown_target');
      const primary = await request(baseUrl, 'POST', '/v1/reports', {
        headers,
        body: { primary_run_id: 'run_missing' },
      });
      assert.equal(primary.status, 400);
      assert.equal(primary.json.error, 'unrecognized_scope');
      const metadata = await request(baseUrl, 'POST', '/v1/reports', {
        headers,
        body: { metadata: { target_ids: ['tgt_1'] } },
      });
      assert.equal(metadata.status, 400);
      assert.equal(metadata.json.error, 'unrecognized_scope');
      assert.deepEqual(metadata.json.fields, ['metadata.target_ids']);
      assert.deepEqual(counts(), before);

      const listed = await get(baseUrl, '/v1/reports', headers);
      const caps = await get(baseUrl, '/v1/reports/capabilities', headers);
      assert.equal(listed.status, 200);
      assert.equal(caps.status, 200);
      assert.deepEqual(caps.json.capabilities, listed.json.capabilities);
      assert.deepEqual(caps.json.capabilities.scope.fields, ['target_ids', 'target_group_ids', 'run_ids']);
      assert.equal(caps.json.capabilities.scope.max_ids, MAX_REPORT_SCOPE_IDS);
      assert.equal(caps.json.capabilities.scope.declared_members_cap, MAX_DECLARED_MEMBERS);
      assert.equal(caps.json.capabilities.scope.omitted, 'tenant');
      assert.equal(caps.json.capabilities.capture.runs_when_run_ids_omitted, MAX_CAPTURED_RUNS);
      assert.equal(caps.json.capabilities.capture.findings, MAX_SNAPSHOT_FINDINGS);
      assert.equal(caps.json.capabilities.capture.evidence, MAX_SNAPSHOT_EVIDENCE);
      assert.equal(caps.json.capabilities.readiness_score.scoped, 'unknown');
      assert.equal(caps.json.capabilities.readiness_score.reason, 'published_readiness_formula_is_tenant_wide');
      assert.equal(caps.json.capabilities.snapshot_frozen, true);
      assert.equal(Object.hasOwn(caps.json.capabilities, 'primary_run_id'), false);
      assert.deepEqual(counts(), before);
      assert.equal((await get(baseUrl, '/v1/reports/capabilities', demoHeaders('viewer'))).status, 200);

      const created = await request(baseUrl, 'POST', '/v1/reports', {
        headers,
        body: { title: 'Tenant snapshot' },
      });
      assert.equal(created.status, 201, created.text);
      assert.equal(typeof created.json.id, 'string');
      assert.equal(created.json.summary.snapshot_frozen, true);
      assert.equal(created.json.summary.primary_run_id, null);
      assert.equal(created.json.summary.readiness_score_scope, 'tenant');
      assert.equal(store.reports.length, before.reports + 1);
      assert.equal(store.auditLog.some((entry) => entry.action === 'report.generated'), true);
      assert.equal(store.notificationEvents.length, before.notifications);
      const afterGet = store.reports.length;
      assert.equal((await get(baseUrl, '/v1/reports', headers)).status, 200);
      assert.equal(store.reports.length, afterGet);

      const inventory = await get(baseUrl, '/v1/targets', headers);
      const proven = inventory.json.items.find((item) => item.id === 'tgt_1');
      assert.equal(proven.verification_state, 'dns_verified');
      assert.equal(proven.eligibility, 'eligible');
      const detail = await get(baseUrl, '/v1/targets/tgt_1', headers);
      assert.equal(detail.json.target.eligibility, 'eligible');
      assert.equal(detail.json.target.eligibility_reason, null);
      assert.equal(detail.json.coverage.runtime_launch_gates, 'not_evaluated');
      store.targetVerifications = [];
      const locked = await get(baseUrl, '/v1/targets', headers);
      assert.equal(locked.json.items.find((item) => item.id === 'tgt_1').eligibility, 'not_runnable_now');
      const lockedDetail = await get(baseUrl, '/v1/targets/tgt_1', headers);
      assert.equal(lockedDetail.json.target.eligibility, 'not_runnable_now');
      assert.equal(lockedDetail.json.target.eligibility_reason, null);
      const secret = 'super-secret-connector';
      store.targetVerifications = [{
        id: 'tv_revoked',
        tenant_id: 'ten_demo',
        target_id: 'tgt_1',
        state: 'provider_verified',
        source_kind: 'provider_account',
        source_ref: {
          connector_id: 'conn_missing',
          provider: 'cloudflare',
          resource_ref_hash: 'zone_hash',
          token: secret,
        },
        transitioned_at: AS_OF,
      }];
      const revokedAnalytics = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?unit=target&limit=200&as_of=${encodeURIComponent(AS_OF)}`,
        headers,
      );
      assert.equal(revokedAnalytics.status, 200);
      const revokedItem = revokedAnalytics.json.items.find((item) => item.id === 'tgt_1');
      assert.equal(revokedItem.verification_state, 'pending');
      assert.equal(JSON.stringify(revokedAnalytics.json).includes(secret), false);
      const asVerified = await get(
        baseUrl,
        `/v1/analytics/declared-hosts?unit=target&verification_state=provider_verified&limit=50&as_of=${encodeURIComponent(AS_OF)}`,
        headers,
      );
      assert.equal(asVerified.json.total, 0);
      assert.equal(asVerified.json.items.some((item) => item.id === 'tgt_1'), false);
      const asPending = await get(
        baseUrl,
        `/v1/targets?unit=target&verification_state=pending&limit=50&as_of=${encodeURIComponent(AS_OF)}`,
        headers,
      );
      assert.equal(asPending.json.items.some((item) => item.id === 'tgt_1'), true);
      assert.equal(JSON.stringify(asPending.json).includes(secret), false);
      const pendingInventory = (await get(baseUrl, '/v1/targets', headers)).json.items.find((item) => item.id === 'tgt_1');
      assert.equal(pendingInventory.verification_state, 'pending');
      assert.equal(pendingInventory.eligibility, 'not_runnable_now');
      assert.equal(pendingInventory.eligibility_reason, null);
    } finally {
      await closeServer(server);
    }
  });

  it('serves the same routes through the Postgres app role', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await seedPostgres(ownerPool);
      const { appUrl, appPool } = await createAppRolePool(ownerPool, databaseName);
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
        const headers = adminHeaders('ten_api');
        const legacy = await get(baseUrl, '/v1/targets', headers);
        assert.equal(legacy.status, 200, legacy.text);
        assert.deepEqual(Object.keys(legacy.json).sort(), ['count', 'items', 'meta']);
        assert.equal(legacy.json.count, 5);
        assert.equal(legacy.json.items.every((item) => item.eligibility === 'not_runnable_now'), true);
        assert.equal(legacy.json.items.every((item) => item.eligibility_reason === null), true);

        const coverage = await get(
          baseUrl,
          `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=50&as_of=${encodeURIComponent(AS_OF)}`,
          headers,
        );
        assert.equal(coverage.status, 200, coverage.text);
        assertDashboardShape(coverage.json);
        assert.equal(coverage.json.denominator, 3);
        assert.equal(coverage.json.units.target_records, 5);
        const example = coverage.json.items.find((item) => item.analytics.host_key === 'example.com');
        assert.equal(example.analytics.member_count, 2);
        assert.equal(coverage.json.items.some((item) => String(item.value).includes('203.0.113.10')), false);
        assert.equal(coverage.text.includes('super-secret'), false);
        const staleHost = coverage.json.items.find((item) => item.id === 'tgt_stale');
        assert.equal(staleHost.analytics.families.waf.bucket, 'stale');
        assert.equal(staleHost.protection_profile.families.waf.status, 'detected');
        assert.equal(staleHost.protection_profile.families.waf.freshness, 'stale');
        const inherited = coverage.json.items.find((item) => item.id === 'tgt_inherit');
        assert.equal(inherited.declaration.criticality.status, 'inherited');
        assert.equal(inherited.declaration.criticality.source, 'target_group');
        assert.equal(inherited.verification_state, null);

        const targets = await get(
          baseUrl,
          `/v1/targets?family=waf&family_status=stale&unit=hostname&limit=200&as_of=${encodeURIComponent(AS_OF)}`,
          headers,
        );
        assert.equal(targets.json.page.total, segmentCount(coverage.json, 'stale'));
        assert.equal(targets.json.items.some((item) => item.id === 'tgt_stale'), true);

        const wide = await get(
          baseUrl,
          '/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1',
          adminHeaders('ten_wide'),
        );
        assert.equal(wide.status, 200, wide.text);
        assert.equal(wide.json.denominator, 5001);
        assert.equal(wide.json.count, 1);
        assert.equal(wide.json.items.length, 1);
        assert.equal(wide.json.complete, true);
        const wideNext = await get(
          baseUrl,
          `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&limit=1&cursor=${encodeURIComponent(wide.json.next_cursor)}`,
          adminHeaders('ten_wide'),
        );
        assert.equal(wideNext.json.denominator, 5001);
        assert.notEqual(wideNext.json.items[0].id, wide.json.items[0].id);

        const version = coverage.json.cohort_version;
        await ownerPool.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
           VALUES ('tgt_late', 'ten_api', 'tg_api', 'fqdn', 'late.example.com', 'late.example.com')`,
        );
        const changed = await get(
          baseUrl,
          `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&as_of=${encodeURIComponent(AS_OF)}&cohort_version=${version}`,
          headers,
        );
        assert.equal(changed.status, 409);
        assert.equal(changed.json.error, 'cohort_changed');
        assert.equal(changed.json.filters.unit, 'hostname');
        assert.equal(changed.json.total, undefined);
        const refetched = await get(
          baseUrl,
          `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&as_of=${encodeURIComponent(AS_OF)}`,
          headers,
        );
        assert.equal(refetched.json.denominator, coverage.json.denominator + 1);
        assert.notEqual(refetched.json.cohort_version, version);

        const hidden = await get(
          baseUrl,
          `/v1/analytics/declared-hosts?family=waf&unit=normalized_hostname&as_of=${encodeURIComponent(AS_OF)}`,
          adminHeaders('ten_other'),
        );
        assert.equal(hidden.json.denominator, 1);
        assert.equal(hidden.text.includes('stale.example.com'), false);
        assert.equal(hidden.text.includes('wide.example.com'), false);

        const runs = await ownerPool.query(`SELECT COUNT(*)::int AS n FROM test_runs`);
        const compatible = await get(baseUrl, '/v1/targets/tgt_host/compatible-checks', headers);
        const ipChecks = await get(baseUrl, '/v1/targets/tgt_ip/compatible-checks', headers);
        assert.equal(compatible.status, 200, compatible.text);
        assert.equal(compatible.json.runtime_launch_gates, 'not_evaluated');
        assert.equal(compatible.json.checks.some((pair) => pair.check_id === MARKER), true);
        assert.equal(ipChecks.json.checks.some((pair) => pair.check_id === MARKER), false);
        assert.equal(compatible.text.includes('probe_profile'), false);
        const runsAfter = await ownerPool.query(`SELECT COUNT(*)::int AS n FROM test_runs`);
        assert.equal(runsAfter.rows[0].n, runs.rows[0].n);
        assert.equal((await get(baseUrl, '/v1/targets/tgt_host/compatible-checks', adminHeaders('ten_other'))).status, 404);

        const exact = await get(baseUrl, `/v1/checks/${MARKER}`, headers);
        assert.equal(exact.status, 200, exact.text);
        assert.equal(exact.json.check.check_id, MARKER);
        assert.equal((await get(baseUrl, '/v1/checks/missing.check.safe', headers)).status, 404);

        const added = await get(baseUrl, '/v1/audit-log?action=target.added&limit=1', headers);
        assert.equal(added.status, 200, added.text);
        assert.equal(added.json.total, 2);
        assert.equal(added.json.items[0].id, 'aud_hi');
        const cursor = decodeCursor(added.json.next_cursor);
        assert.equal(cursor.ts.includes('.100002'), true);
        assert.notEqual(cursor.ts, added.json.items[0].timestamp);
        const older = await get(
          baseUrl,
          `/v1/audit-log?action=target.added&limit=1&cursor=${encodeURIComponent(added.json.next_cursor)}`,
          headers,
        );
        assert.equal(older.json.items[0].id, 'aud_lo');
        const precise = await get(
          baseUrl,
          `/v1/audit-log?action=target.added&since=${encodeURIComponent(HI)}&until=${encodeURIComponent(HI)}`,
          headers,
        );
        assert.deepEqual(precise.json.items.map((entry) => entry.id), ['aud_hi']);
        const own = await get(baseUrl, '/v1/audit-log/aud_hi', headers);
        assert.equal(own.json.entry.id, 'aud_hi');
        assert.equal(own.json.entry.entry_hash, 'h3');
        assert.equal(own.json.entry.prev_hash, 'prev-h3');
        assert.deepEqual(own.json.entry.metadata, { source: 'audit_log' });
        const ranged = await get(
          baseUrl,
          `/v1/audit-log?action=target.added&from=${encodeURIComponent(HI)}&to=${encodeURIComponent(HI)}`,
          headers,
        );
        assert.deepEqual(ranged.json.items.map((entry) => entry.id), ['aud_hi']);
        const reportsBefore = await ownerPool.query(
          `SELECT
             (SELECT COUNT(*)::int FROM reports) AS reports,
             (SELECT COUNT(*)::int FROM audit_logs) AS audit,
             (SELECT COUNT(*)::int FROM notification_events) AS notifications`,
        );
        const rejected = await request(baseUrl, 'POST', '/v1/reports', {
          headers,
          body: { target_ids: ['tgt_other'] },
        });
        assert.equal(rejected.status, 400);
        assert.equal(rejected.json.error, 'unknown_target');
        const reportsAfter = await ownerPool.query(
          `SELECT
             (SELECT COUNT(*)::int FROM reports) AS reports,
             (SELECT COUNT(*)::int FROM audit_logs) AS audit,
             (SELECT COUNT(*)::int FROM notification_events) AS notifications`,
        );
        assert.deepEqual(reportsAfter.rows[0], reportsBefore.rows[0]);
        const capabilities = await get(baseUrl, '/v1/reports/capabilities', headers);
        assert.equal(capabilities.status, 200);
        assert.equal(capabilities.json.capabilities.scope.max_ids, MAX_REPORT_SCOPE_IDS);
        assert.equal(capabilities.json.capabilities.snapshot_frozen, true);
        assert.equal((await get(baseUrl, '/v1/audit-log/aud_hi', adminHeaders('ten_other'))).status, 404);
        assert.equal((await get(baseUrl, '/v1/audit-log/aud_foreign', headers)).status, 404);
        assert.equal((await get(baseUrl, '/v1/audit-log', demoHeaders('viewer', 'ten_api', 'usr_viewer'))).status, 403);
        const filtered = await get(baseUrl, '/v1/audit-log?action=target.added', headers);
        assert.equal(filtered.json.total, 2);
        assert.equal(filtered.json.items.some((entry) => entry.action === 'rbac.denied'), false);
      } finally {
        await closeServer(server);
        await runtime.close();
        await closePgPool(appPool);
      }
    }, availability.env);
  });
});

function target(id, kind, value, declaration, metadata = {}) {
  return {
    id,
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    kind,
    value,
    declaration_json: declaration,
    metadata,
  };
}

function edge(id, targetId, conflict, wafStatus, cdnStatus, observedAt) {
  return {
    id,
    tenant_id: 'ten_demo',
    target_id: targetId,
    target_group_id: 'tg_1',
    waf_status: wafStatus,
    cdn_status: cdnStatus,
    waf_vendor: 'waf-vendor',
    cdn_provider: 'cdn-vendor',
    conflicting_vendor_signals: conflict,
    observed_at: observedAt,
    evidence_json: { authorization: 'super-secret-evidence' },
  };
}

function auditRow(id, tenantId, timestamp, sequence, actor, action, resourceType, resourceId) {
  return {
    id,
    tenant_id: tenantId,
    timestamp,
    sequence,
    actor_user_id: actor,
    actor_role: 'admin',
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    prev_hash: `prev-${id}`,
    entry_hash: `hash-${id}`,
    metadata: { source: 'audit_log', id },
  };
}

async function createAppRolePool(ownerPool, databaseName) {
  await ensureHarnessAppRole(ownerPool);
  await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
  const url = new URL(databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
  return { appUrl, appPool: createPgPool({ ASTRANULL_DATABASE_URL: appUrl }) };
}

async function seedPostgres(pool) {
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES ('ten_api', 'API'), ('ten_other', 'Other'), ('ten_wide', 'Wide')`,
  );
  await pool.query(
    `INSERT INTO environments (id, tenant_id, name)
     VALUES ('env_api', 'ten_api', 'API'), ('env_other', 'ten_other', 'Other'), ('env_wide', 'ten_wide', 'Wide')`,
  );
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name, declaration_json)
     VALUES
       ('tg_api', 'ten_api', 'env_api', 'api', $1::jsonb),
       ('tg_other', 'ten_other', 'env_other', 'other', '{}'::jsonb),
       ('tg_wide', 'ten_wide', 'env_wide', 'wide', '{}'::jsonb)`,
    [JSON.stringify({ criticality: 'high', service_roles: ['website'], owner_label: 'Group Owner' })],
  );
  const rows = [
    ['tgt_host', 'ten_api', 'tg_api', 'fqdn', 'Example.com', 'example.com', { service_roles: ['website'], criticality: 'critical' }, { tags: ['prod'], connector_token: 'super-secret-metadata' }],
    ['tgt_url', 'ten_api', 'tg_api', 'url', 'https://Example.com/login', 'https://example.com/login', { service_roles: ['login'] }, {}],
    ['tgt_stale', 'ten_api', 'tg_api', 'fqdn', 'stale.example.com', 'stale.example.com', { service_roles: ['website'] }, {}],
    ['tgt_inherit', 'ten_api', 'tg_api', 'fqdn', 'inherited.example.com', 'inherited.example.com', {}, {}],
    ['tgt_ip', 'ten_api', 'tg_api', 'ip', '203.0.113.10', '203.0.113.10', { service_roles: ['network'] }, {}],
    ['tgt_other', 'ten_other', 'tg_other', 'fqdn', 'other.example.com', 'other.example.com', { service_roles: ['api'] }, {}],
  ];
  for (const [id, tenant, group, kind, value, normalized, declaration, metadata] of rows) {
    await pool.query(
      `INSERT INTO targets (
         id, tenant_id, target_group_id, kind, value, normalized_value, declaration_json, metadata_json
       ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)`,
      [id, tenant, group, kind, value, normalized, JSON.stringify(declaration), JSON.stringify(metadata)],
    );
  }
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
     SELECT 'w' || lpad(g::text, 5, '0'), 'ten_wide', 'tg_wide', 'fqdn',
            'h' || g::text || '.wide.example.com', 'h' || g::text || '.wide.example.com'
     FROM generate_series(1, 5001) AS g`,
  );
  await pool.query(
    `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, completed_at)
     VALUES
       ('run_host', 'ten_api', 'tg_api', 'tgt_host', 'edge.fingerprint', 'completed', $1),
       ('run_url', 'ten_api', 'tg_api', 'tgt_url', 'edge.fingerprint', 'completed', $1),
       ('run_stale', 'ten_api', 'tg_api', 'tgt_stale', 'edge.fingerprint', 'completed', NULL)`,
    [RECENT],
  );
  const edges = [
    ['edge_host', 'tgt_host', 'run_host', false, 'detected', 'not_detected', RECENT],
    ['edge_url', 'tgt_url', 'run_url', false, 'detected', 'not_detected', RECENT],
    ['edge_stale', 'tgt_stale', 'run_stale', false, 'detected', 'not_detected', OLD],
  ];
  for (const [id, targetId, runId, conflict, wafStatus, cdnStatus, observedAt] of edges) {
    await pool.query(
      `INSERT INTO target_edge_detections (
         id, tenant_id, target_group_id, target_id, test_run_id, waf_status, cdn_status,
         waf_vendor, cdn_provider, conflicting_vendor_signals, observed_at, evidence_json
       ) VALUES ($1, 'ten_api', 'tg_api', $2, $3, $4, $5, 'waf-vendor', 'cdn-vendor', $6, $7, $8::jsonb)`,
      [id, targetId, runId, wafStatus, cdnStatus, conflict, observedAt, JSON.stringify({ authorization: 'super-secret-evidence' })],
    );
  }
  await pool.query(
    `INSERT INTO audit_logs (
       id, tenant_id, timestamp, sequence, prev_hash, entry_hash, actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
     ) VALUES
       ('aud_lo', 'ten_api', $1, 2, 'prev-h2', 'h2', 'usr_admin', 'admin', 'target.added', 'target', 'tgt_host', '{}'::jsonb),
       ('aud_hi', 'ten_api', $2, 3, 'prev-h3', 'h3', 'usr_admin', 'admin', 'target.added', 'target', 'tgt_host', '{"source":"audit_log"}'::jsonb),
       ('aud_other', 'ten_api', $3, 4, 'prev-h4', 'h4', 'usr_other', 'admin', 'target.updated', 'target_group', 'tg_api', '{}'::jsonb),
       ('aud_foreign', 'ten_other', $2, 1, 'prev-hb', 'hb', 'usr_foreign', 'admin', 'target.added', 'target', 'tgt_other', '{}'::jsonb)`,
    [LO, HI, LATER],
  );
}
