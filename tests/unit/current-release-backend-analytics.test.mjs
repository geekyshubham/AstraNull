import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { OBSERVATION_FRESHNESS_POLICY } from '../../src/services/protectionProfile.mjs';
import { presentTargetDeclaration } from '../../src/lib/targetDeclarations.mjs';
import {
  CITED_OBSERVATION_FRESHNESS_POLICY,
  DeclaredHostQueryError,
  applyDeclaredTargetQuery,
  queryDeclaredHostAnalytics,
  queryDeclaredHostAnalyticsFromReader,
} from '../../src/services/declaredHostAnalytics.mjs';

const AS_OF = '2026-10-04T00:00:00.000Z';

function family(status, freshness = 'current', extra = {}) {
  return { status, freshness, conflict: false, provider: null, observed_at: AS_OF, ...extra };
}

function declared({
  roles = [],
  criticality = null,
  owner = null,
  roleStatus,
  critStatus,
  ownerStatus,
  purpose = null,
} = {}) {
  return {
    purpose,
    purpose_status: purpose ? 'declared' : 'unassigned',
    purpose_source: purpose ? 'target' : null,
    service_roles: roles,
    service_roles_status: roleStatus ?? (roles.length ? 'declared' : 'unassigned'),
    service_roles_source: roles.length ? 'target' : null,
    owner: {
      status: ownerStatus ?? (owner ? 'declared' : 'unassigned'),
      label: owner,
      source: owner ? 'target' : null,
    },
    criticality: {
      status: critStatus ?? (criticality ? 'declared' : 'unassigned'),
      value: criticality,
      source: criticality ? 'target' : null,
    },
  };
}

function row(partial) {
  return {
    tags: [],
    verification_state: null,
    findings_count: 0,
    last_validation_at: null,
    ...partial,
  };
}

function cohort() {
  return [
    row({
      id: 'tgt_host',
      kind: 'fqdn',
      value: 'Example.com.',
      target_group_id: 'tg_a',
      verification_state: null,
      findings_count: 0,
      declaration: declared({ roles: ['website'], criticality: 'critical', owner: 'Edge' }),
      protection_profile: { families: { waf: family('detected'), cdn: family('not_detected') } },
    }),
    row({
      id: 'tgt_url',
      kind: 'url',
      value: 'https://User:secret@Example.com:443/login',
      target_group_id: 'tg_a',
      verification_state: 'dns_verified',
      findings_count: 0,
      declaration: declared({ roles: ['login'] }),
      protection_profile: { families: { waf: family('detected'), cdn: family('not_detected') } },
    }),
    row({
      id: 'tgt_api',
      kind: 'fqdn',
      value: 'api.example.com',
      tags: ['prod'],
      target_group_id: 'tg_a',
      verification_state: 'unverified',
      findings_count: 2,
      declaration: declared({ roles: ['api', 'login'], criticality: 'high', owner: 'Edge' }),
      protection_profile: {
        families: {
          waf: family('detected', 'stale'),
          cdn: family('inconclusive', 'current'),
        },
      },
    }),
    row({
      id: 'tgt_tag',
      kind: 'fqdn',
      value: 'api.tags.example.com',
      tags: ['api', 'login'],
      verification_state: 'unverified',
      findings_count: 0,
      declaration: declared({ roles: ['dns'] }),
      protection_profile: { families: { waf: family('not_checked', 'unknown'), cdn: family('not_recorded', 'unknown') } },
    }),
    row({
      id: 'tgt_unknown',
      kind: 'fqdn',
      value: 'unknown.example.com',
      declaration: null,
      findings_count: null,
      protection_profile: null,
      reachability: 'unreachable',
    }),
    row({
      id: 'tgt_plain',
      kind: 'fqdn',
      value: 'plain.example.com',
      declaration: declared({ roles: [] }),
      protection_profile: { families: { waf: family('not_checked', 'unknown'), cdn: family('not_checked', 'unknown') } },
    }),
    row({
      id: 'tgt_ip',
      kind: 'ip',
      value: '203.0.113.10',
      declaration: declared({ roles: ['network'] }),
      protection_profile: { families: { waf: family('not_checked', 'unknown'), cdn: family('not_checked', 'unknown') } },
    }),
    row({
      id: 'tgt_ipurl',
      kind: 'url',
      value: 'https://203.0.113.10/admin',
      declaration: declared({ roles: [] }),
      protection_profile: { families: { waf: family('unknown', 'unknown'), cdn: family('unknown', 'unknown') } },
    }),
    row({
      id: 'tgt_cidr',
      kind: 'cidr',
      value: '203.0.113.0/24',
      declaration: declared({ roles: [] }),
    }),
    row({
      id: 'tgt_conflict_a',
      kind: 'url',
      value: 'https://split.example.com/a',
      declaration: declared({ roles: ['website'] }),
      protection_profile: { families: { waf: family('detected'), cdn: family('detected') } },
    }),
    row({
      id: 'tgt_conflict_b',
      kind: 'url',
      value: 'https://split.example.com/b',
      declaration: declared({ roles: ['website'] }),
      protection_profile: {
        families: {
          waf: family('not_detected', 'current', { conflict: true }),
          cdn: family('detected'),
        },
      },
    }),
    row({
      id: 'tgt_archived',
      kind: 'fqdn',
      value: 'archived.example.com',
      group_archived_at: AS_OF,
      declaration: declared({ roles: ['website'] }),
    }),
    row({
      id: 'tgt_deleted',
      kind: 'fqdn',
      value: 'deleted.example.com',
      deleted_at: AS_OF,
      declaration: declared({ roles: ['api'] }),
    }),
  ];
}

function analytics(query, rows = cohort()) {
  return queryDeclaredHostAnalytics(rows, query, { asOf: AS_OF });
}

describe('declared host analytics predicate', () => {
  it('cites the observation policy and does not apply it', () => {
    assert.equal(CITED_OBSERVATION_FRESHNESS_POLICY.id, OBSERVATION_FRESHNESS_POLICY.id);
    assert.equal(CITED_OBSERVATION_FRESHNESS_POLICY.version, OBSERVATION_FRESHNESS_POLICY.version);
    assert.equal(CITED_OBSERVATION_FRESHNESS_POLICY.max_age_ms, OBSERVATION_FRESHNESS_POLICY.max_age_ms);
    assert.equal(CITED_OBSERVATION_FRESHNESS_POLICY.applied, false);
  });

  it('dedupes hostname and URL hosts and keeps IP and CIDR out of the host denominator', () => {
    const hosts = analytics({ unit: 'hostname', limit: 50 });
    const targets = analytics({ unit: 'target', limit: 50 });
    const example = hosts.items.find((item) => item.analytics.host_key === 'example.com');
    assert.equal(example.analytics.member_count, 2);
    assert.deepEqual(example.analytics.target_ids, ['tgt_host', 'tgt_url']);
    assert.equal(hosts.items.some((item) => item.id === 'tgt_ip' || item.id === 'tgt_ipurl' || item.id === 'tgt_cidr'), false);
    assert.equal(hosts.items.some((item) => item.value === 'archived.example.com' || item.value === 'deleted.example.com'), false);
    assert.equal(hosts.total, 6);
    assert.equal(targets.total, 11);
    assert.equal(targets.items.some((item) => item.id === 'tgt_ip'), true);
    assert.equal(targets.items.some((item) => item.reachability === 'unreachable'), true);
    assert.notEqual(hosts.total, 999);
  });

  it('overlaps multi-role hosts and does not read roles from tags or hostnames', () => {
    const result = analytics({ unit: 'hostname' });
    const { segments } = result.rollup;
    assert.equal(result.total, segments.all.count);
    assert.ok(segments.api.count + segments.login.count + segments.website.count + segments.unclassified.count > segments.all.count);
    const apiIds = applyDeclaredTargetQuery(cohort(), { ...segments.api.list_query, limit: 50 }, { asOf: AS_OF }).items
      .map((item) => item.analytics.host_key);
    assert.deepEqual(apiIds, ['api.example.com']);
    assert.equal(segments.api.list_query_exact, true);
    assert.equal(segments.login.count >= 2, true);
    const tagHost = result.items.find((item) => item.analytics.host_key === 'api.tags.example.com');
    assert.equal(tagHost.analytics.unclassified, true);
    assert.equal(tagHost.analytics.segment_roles.includes('api'), false);
    assert.equal(segments.unclassified.count >= 2, true);
  });

  it('keeps unknown, not_checked, inconclusive, stale, and conflict distinct', () => {
    const result = analytics({ unit: 'hostname' });
    const waf = result.rollup.segments.all.waf;
    assert.ok(waf.unknown >= 1);
    assert.ok(waf.not_checked >= 1);
    assert.ok(waf.stale >= 1);
    assert.ok(waf.conflict >= 1);
    assert.equal(result.rollup.segments.all.cdn.inconclusive >= 1, true);
    assert.equal(result.rollup.segments.all.cdn.not_recorded >= 1, true);
    const stale = applyDeclaredTargetQuery(cohort(), {
      unit: 'hostname',
      family: 'waf',
      family_status: 'stale',
      limit: 50,
    });
    assert.equal(stale.total, waf.stale);
    assert.equal(stale.items.some((item) => item.analytics.families.waf.bucket === 'detected'), false);
    const past = analytics({ unit: 'hostname', family: 'waf', family_status: 'stale' });
    const older = queryDeclaredHostAnalytics(cohort(), {
      unit: 'hostname',
      family: 'waf',
      family_status: 'stale',
    }, { asOf: '2001-01-01T00:00:00.000Z' });
    assert.equal(older.total, past.total);
    assert.equal(older.historical, false);
    assert.equal(older.snapshot_id, null);
    assert.equal(older.scope, 'current');
    assert.equal(older.as_of, '2001-01-01T00:00:00.000Z');
    assert.equal(older.as_of_semantics, 'caller_evaluation_clock');
  });

  it('returns null percentages for an empty denominator and zero for an empty bucket', () => {
    const empty = analytics({ unit: 'hostname', criticality: 'low' });
    assert.equal(empty.total, 0);
    assert.equal(empty.rollup.segments.all.count, 0);
    assert.equal(empty.rollup.segments.all.percentage, null);
    assert.equal(empty.rollup.segments.all.waf.percentages.detected, null);
    assert.equal(empty.rollup.segments.all.cdn.percentages.not_detected, null);
    const all = analytics({ unit: 'hostname' });
    assert.equal(all.rollup.segments.all.waf.percentages.not_detected, 0);
    assert.equal(all.rollup.total, all.total);
  });

  it('does not treat missing verification or findings as unverified or clear', () => {
    const unverified = analytics({ unit: 'hostname', verification_state: 'unverified' });
    assert.equal(unverified.items.some((item) => item.analytics.host_key === 'unknown.example.com'), false);
    assert.equal(unverified.items.some((item) => item.analytics.host_key === 'api.example.com'), true);
    const clear = analytics({ unit: 'hostname', has_open_finding: 'false' });
    assert.equal(clear.items.some((item) => item.id === 'tgt_unknown'), false);
    const open = analytics({ unit: 'target', has_open_finding: true });
    assert.deepEqual(open.items.map((item) => item.id), ['tgt_api']);
  });

  it('keeps the aggregate stable when the page limit is 1', () => {
    const full = analytics({ unit: 'hostname', limit: 50 });
    const page = analytics({ unit: 'hostname', limit: 1 });
    assert.equal(page.count, 1);
    assert.equal(page.items.length, 1);
    assert.equal(page.total, full.total);
    assert.equal(page.rollup.segments.all.count, full.total);
    assert.ok(page.next_cursor);
    const seen = new Set();
    let cursor = null;
    let guard = 0;
    while (guard < 20) {
      const next = applyDeclaredTargetQuery(cohort(), { unit: 'hostname', limit: 1, cursor }, { asOf: AS_OF });
      assert.equal(next.total, full.total);
      for (const item of next.items) {
        assert.equal(seen.has(item.analytics.host_key), false);
        seen.add(item.analytics.host_key);
      }
      cursor = next.next_cursor;
      guard += 1;
      if (!cursor) break;
    }
    assert.equal(seen.size, full.total);
  });

  it('rejects unknown params, bad enums, and bad cursors', () => {
    assert.throws(() => analytics({ unit: 'hostname', posture: 'protected' }), (error) => {
      assert.equal(error instanceof DeclaredHostQueryError, true);
      assert.equal(error.code, 'unknown_query_param');
      return true;
    });
    assert.throws(() => analytics({ family_status: 'detected' }), (error) => {
      assert.equal(error.code, 'family_required');
      return true;
    });
    assert.throws(() => analytics({ verification_state: 'nope' }), (error) => {
      assert.equal(error.code, 'invalid_query_value');
      return true;
    });
    assert.throws(() => analytics({ limit: 0 }), (error) => {
      assert.equal(error.code, 'invalid_limit');
      return true;
    });
    assert.throws(() => analytics({ cursor: '@@@' }), (error) => {
      assert.equal(error.code, 'invalid_cursor');
      return true;
    });
    const cursor = analytics({ unit: 'hostname', limit: 1 }).next_cursor;
    assert.throws(() => analytics({ unit: 'target', cursor }), (error) => {
      assert.equal(error.code, 'invalid_cursor');
      return true;
    });
  });

  it('round-trips an exact segment and family list_query', () => {
    const result = analytics({ unit: 'hostname', tag: 'prod' });
    const segment = result.rollup.segments.api;
    assert.equal(segment.list_query_exact, true);
    const listed = applyDeclaredTargetQuery(cohort(), { ...segment.list_query, limit: 50 }, { asOf: AS_OF });
    assert.equal(listed.total, segment.count);
    const bucket = segment.waf.list_queries.stale;
    assert.equal(bucket.list_query_exact, true);
    const stale = applyDeclaredTargetQuery(cohort(), { ...bucket.list_query, limit: 50 }, { asOf: AS_OF });
    assert.equal(stale.total, segment.waf.stale);
    assert.equal(stale.filters.family, 'waf');
    const combined = queryDeclaredHostAnalytics(cohort(), segment.list_query, { asOf: AS_OF });
    assert.equal(combined.total, combined.rollup.total);
    assert.equal(combined.filters.unit, combined.rollup.filters.unit);
  });

  it('uses an inherited declaration and ignores a WAF-asset count', () => {
    const declaration = presentTargetDeclaration({}, { criticality: 'high', service_roles: ['website'], owner_label: 'Group Owner' });
    const rows = [row({
      id: 'tgt_inherited',
      kind: 'fqdn',
      value: 'inherited.example.com',
      declaration,
      waf_asset_count: 999,
      protection_profile: { families: { waf: family('not_checked', 'unknown'), cdn: family('not_checked', 'unknown') } },
    })];
    const result = analytics({ unit: 'hostname', criticality: 'high', owner_status: 'inherited' }, rows);
    assert.equal(result.total, 1);
    assert.equal(result.rollup.segments.website.count, 1);
    assert.equal(result.rollup.segments.all.count, 1);
    assert.notEqual(result.total, 999);
  });

  it('does not report the read cap as the estate total', async () => {
    const rows = [
      row({ id: 'a', kind: 'fqdn', value: 'a.example.com', declaration: declared() }),
      row({ id: 'b', kind: 'fqdn', value: 'b.example.com', declaration: declared() }),
    ];
    let calls = 0;
    const result = await queryDeclaredHostAnalyticsFromReader(async ({ afterId, limit }) => {
      calls += 1;
      const pending = rows.filter((item) => afterId == null || item.id > afterId);
      return pending.slice(0, limit);
    }, { unit: 'hostname' }, { asOf: AS_OF, rowBound: 1, batchSize: 1 });
    assert.equal(result.complete, false);
    assert.equal(result.total, null);
    assert.equal(result.rollup, null);
    assert.deepEqual(result.items, []);
    assert.notEqual(result.total, result.read_bound);
    assert.equal(calls, 2);
  });

  it('accepts explicit UI aliases and rejects a conflicting alias', () => {
    const alias = analytics({
      search: 'tgt_api',
      group: 'tg_a',
      verification: 'unverified',
      role: 'api',
      unit: 'normalized_hostname',
    });
    const canonical = analytics({
      q: 'tgt_api',
      target_group_id: 'tg_a',
      verification_state: 'unverified',
      service_role: 'api',
      unit: 'hostname',
    });
    assert.equal(alias.total, 1);
    assert.equal(alias.total, canonical.total);
    assert.equal(alias.filters.unit, 'hostname');
    assert.equal(alias.filters.service_role, 'api');
    assert.equal(alias.cohort_version, canonical.cohort_version);
    assert.throws(() => analytics({ search: 'a', q: 'b' }), (error) => {
      assert.equal(error.code, 'invalid_query_value');
      assert.equal(error.status, 400);
      return true;
    });
    assert.throws(() => analytics({ unit: 'hosts' }), (error) => {
      assert.equal(error.code, 'invalid_query_value');
      return true;
    });
    assert.throws(() => analytics({ origin_status: 'exposed' }), (error) => {
      assert.equal(error.code, 'unknown_query_param');
      return true;
    });
  });

  it('rejects a changed cohort and a cursor bound to other filters or another clock', () => {
    const first = analytics({ unit: 'hostname', limit: 1 });
    assert.equal(first.cohort_version.length, 32);
    assert.throws(() => analytics({ unit: 'hostname', limit: 1, cohort_version: '0123456789abcdef' }), (error) => {
      assert.equal(error.code, 'cohort_changed');
      assert.equal(error.status, 409);
      assert.equal(error.filters.unit, 'hostname');
      assert.equal(Object.hasOwn(error, 'total'), false);
      return true;
    });
    const extra = cohort();
    extra.push(row({
      id: 'tgt_url_2',
      kind: 'url',
      value: 'https://example.com/extra',
      declaration: declared({ roles: ['website'] }),
      protection_profile: { families: { waf: family('detected'), cdn: family('not_detected') } },
    }));
    const joined = queryDeclaredHostAnalytics(extra, { unit: 'hostname' }, { asOf: AS_OF });
    assert.equal(joined.total, first.total);
    assert.equal(joined.units.target_records, first.units.target_records + 1);
    assert.notEqual(joined.cohort_version, first.cohort_version);
    assert.throws(
      () => queryDeclaredHostAnalytics(extra, {
        unit: 'hostname',
        cohort_version: first.cohort_version,
      }, { asOf: AS_OF }),
      (error) => error.code === 'cohort_changed' && error.filters.unit === 'hostname',
    );
    assert.throws(() => analytics({ unit: 'hostname', limit: 1, tag: 'prod', cursor: first.next_cursor }), (error) => {
      assert.equal(error.code, 'cursor_filter_mismatch');
      assert.equal(error.status, 409);
      assert.equal(error.filters.unit, 'hostname');
      return true;
    });
    assert.throws(() => queryDeclaredHostAnalytics(cohort(), {
      unit: 'hostname',
      limit: 1,
      cursor: first.next_cursor,
      as_of: '2001-01-01T00:00:00.000Z',
    }, { asOf: '2001-01-01T00:00:00.000Z' }), (error) => {
      assert.equal(error.code, 'cursor_clock_mismatch');
      assert.equal(error.status, 409);
      assert.equal(error.as_of, '2001-01-01T00:00:00.000Z');
      return true;
    });
  });

  it('counts a 10000 row snapshot exactly when no row bound is set', async () => {
    const rows = Array.from({ length: 10000 }, (_, index) => row({
      id: `h${String(index).padStart(5, '0')}`,
      kind: 'fqdn',
      value: `h${index}.example.com`,
      declaration: declared(),
    }));
    const result = await queryDeclaredHostAnalyticsFromReader(async ({ afterId, limit }) => {
      const start = afterId == null ? 0 : rows.findIndex((item) => item.id === afterId) + 1;
      return rows.slice(start, start + limit);
    }, { unit: 'hostname', limit: 50 }, { asOf: AS_OF });
    assert.equal(result.complete, true);
    assert.equal(result.total, 10000);
    assert.equal(result.count, 50);
    assert.equal(result.units.normalized_hosts, 10000);
    assert.equal(result.units.target_records, 10000);
    assert.equal(result.rollup.total, 10000);
    assert.notEqual(result.total, 5000);
  });
});
