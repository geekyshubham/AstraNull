import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { boundCheckRows, evidenceBackedVerdict, recentRunRow } from '../../src/lib/targetDetailRows.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import { getTargetGroup } from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const TARGET = { id: 'tgt_web', tenant_id: 'ten_demo', target_group_id: 'tg_web', kind: 'fqdn', value: 'web.example.test' };
const RUNNABLE = 'origin.leak_scan.safe';
const OTHER_RUNNABLE = 'origin.direct_bypass.safe';
const SOC_GATED = 'l3.connection_table_exhaustion.request_only';
const URL_ONLY = 'path.protected_canary.safe';
const EDGE = 'waf.fingerprint.safe';

const POLICIES = [
  { id: 'pol_group', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: null, check_id: RUNNABLE, cadence: 'daily', state: 'active' },
  { id: 'pol_target', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: 'tgt_web', check_id: RUNNABLE, cadence: 'weekly', state: 'paused' },
  { id: 'pol_other_target', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: 'tgt_other', check_id: OTHER_RUNNABLE, cadence: 'daily', state: 'active' },
  { id: 'pol_archived', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: null, check_id: OTHER_RUNNABLE, cadence: 'daily', state: 'active', archived_at: '2026-09-01T00:00:00.000Z' },
  { id: 'pol_soc', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: null, check_id: SOC_GATED, cadence: 'manual', state: 'active' },
  { id: 'pol_url_only', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: null, check_id: URL_ONLY, cadence: 'manual', state: 'active' },
  { id: 'pol_other_group', tenant_id: 'ten_demo', target_group_id: 'tg_other', target_id: null, check_id: OTHER_RUNNABLE, cadence: 'daily', state: 'active' },
];

const RUNS = [
  { id: 'run_backed', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: 'tgt_web', check_id: RUNNABLE, policy_id: 'pol_group', status: 'verdicted', started_at: '2026-09-20T10:00:00.000Z', completed_at: '2026-09-20T10:02:00.000Z' },
  { id: 'run_unbacked', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: 'tgt_web', check_id: RUNNABLE, status: 'verdicted', verdict: 'pass', started_at: '2026-09-19T10:00:00.000Z' },
  { id: 'run_edge', tenant_id: 'ten_demo', target_group_id: 'tg_web', target_id: 'tgt_web', check_id: EDGE, status: 'verdicted', started_at: '2026-09-18T10:00:00.000Z', completed_at: '2026-09-18T10:01:00.000Z' },
];

const VERDICTS = [
  { id: 'vd_backed', tenant_id: 'ten_demo', test_run_id: 'run_backed', verdict: 'pass', evidence_ids: ['evt_probe', 'evt_agent'], created_at: '2026-09-20T10:02:00.000Z' },
  { id: 'vd_unbacked', tenant_id: 'ten_demo', test_run_id: 'run_unbacked', verdict: 'fail', evidence_ids: [], created_at: '2026-09-19T10:02:00.000Z' },
];

function seedDevStore() {
  freshStore();
  const store = getStore();
  store.targetGroups.push({ id: 'tg_web', tenant_id: 'ten_demo', environment_id: 'env_demo', name: 'Web' });
  store.targets.push(
    { ...TARGET, created_at: '2026-09-01T00:00:00.000Z' },
    { id: 'tgt_other', tenant_id: 'ten_demo', target_group_id: 'tg_web', kind: 'fqdn', value: 'other.example.test', created_at: '2026-09-01T00:00:00.000Z' },
  );
  store.targetVerifications = [
    { id: 'tv_web', tenant_id: 'ten_demo', target_id: 'tgt_web', state: 'dns_verified', transitioned_at: '2026-09-02T00:00:00.000Z' },
    { id: 'tv_other', tenant_id: 'ten_demo', target_id: 'tgt_other', state: 'dns_verified', transitioned_at: '2026-09-02T00:00:00.000Z' },
  ];
  store.testPolicies = POLICIES.map((policy) => ({ ...policy }));
  store.testRuns.push(...RUNS.map((run) => ({ ...run })));
  store.verdicts.push(...VERDICTS.map((verdict) => ({ ...verdict })));
}

function assertTargetDetailBindings(detail) {
  assert.deepEqual(detail.checks_applied, [{
    check_id: RUNNABLE,
    policy_id: 'pol_target',
    policy_state: 'paused',
    binding_scope: 'target',
    cadence: 'weekly',
    last_verdict: 'pass',
    last_run_id: 'run_backed',
    last_ran_at: '2026-09-20T10:00:00.000Z',
  }]);
  assert.equal(detail.meta.checks_empty_reason, null);

  const byId = Object.fromEntries(detail.runs_recent.map((run) => [run.run_id, run]));
  assert.deepEqual(byId.run_backed, {
    run_id: 'run_backed',
    policy_id: 'pol_group',
    check_id: RUNNABLE,
    status: 'verdicted',
    verdict: 'pass',
    verdict_id: 'vd_backed',
    evidence_ids: ['evt_probe', 'evt_agent'],
    started_at: '2026-09-20T10:00:00.000Z',
    completed_at: '2026-09-20T10:02:00.000Z',
  });
  assert.equal(byId.run_unbacked.status, 'verdicted');
  assert.equal(byId.run_unbacked.verdict, 'fail');
  assert.deepEqual(byId.run_unbacked.evidence_ids, []);
  assert.equal(byId.run_edge.verdict, 'unknown', 'run status is never presented as a verdict');

  assert.deepEqual(detail.edge_detection_request, {
    test_run_id: 'run_edge',
    run_status: 'verdicted',
    started_at: '2026-09-18T10:00:00.000Z',
    completed_at: '2026-09-18T10:01:00.000Z',
  });
}

describe('target detail bindings and run evidence (dev JSON)', () => {
  beforeEach(seedDevStore);

  it('derives bound checks from test policies and returns run lifecycle plus verdict evidence', () => {
    const detail = getTargetDetail(CTX, 'tgt_web');
    assertTargetDetailBindings(detail);
    assert.equal(detail.verification.state, 'dns_verified');
  });

  it('keeps bound checks empty with a policy-specific reason when no policy binds the target', () => {
    getStore().testPolicies = [];
    const detail = getTargetDetail(CTX, 'tgt_web');
    assert.deepEqual(detail.checks_applied, []);
    assert.match(detail.meta.checks_empty_reason, /test policy/);
  });

  it('reports the live group ownership summary from effective target verification', () => {
    const group = getTargetGroup(CTX, 'tg_web');
    assert.equal(group.ownership_status, 'dns_verified');
    getStore().targetVerifications.push({ id: 'tv_other_2', tenant_id: 'ten_demo', target_id: 'tgt_other', state: 'pending', transitioned_at: '2026-09-03T00:00:00.000Z' });
    assert.equal(getTargetGroup(CTX, 'tg_web').ownership_status, 'pending');
  });
});

function runRow(run) {
  const verdict = VERDICTS.find((row) => row.test_run_id === run.id);
  return {
    id: run.id,
    policy_id: run.policy_id ?? null,
    check_id: run.check_id,
    status: run.status,
    started_at: new Date(run.started_at),
    created_at: new Date(run.started_at),
    completed_at: run.completed_at ? new Date(run.completed_at) : null,
    verdict_id: verdict?.id ?? null,
    verdict: verdict?.verdict ?? null,
    evidence_ids: verdict?.evidence_ids ?? null,
  };
}

function postgresPool() {
  const client = {
    async query(text, params = []) {
      const sql = String(text);
      if (sql.includes('SELECT * FROM targets WHERE')) {
        return { rows: [{ ...TARGET, metadata_json: {}, created_at: new Date('2026-09-01T00:00:00.000Z') }] };
      }
      if (sql.includes('COUNT(*) FILTER')) return { rows: [{ open_count: 0, closed_count: 0 }] };
      if (sql.includes('DISTINCT ON (r.check_id)')) {
        const wanted = new Set(params[2]);
        const latest = new Map();
        for (const run of RUNS) {
          if (!wanted.has(run.check_id) || latest.has(run.check_id)) continue;
          latest.set(run.check_id, runRow(run));
        }
        return { rows: [...latest.values()] };
      }
      if (sql.includes('FROM test_runs')) return { rows: RUNS.map(runRow) };
      if (sql.includes('FROM test_policies')) {
        return {
          rows: POLICIES.filter((policy) => policy.target_group_id === params[1]
            && (!policy.target_id || policy.target_id === params[2])
            && !policy.archived_at),
        };
      }
      if (sql.includes('FROM target_verification_current')) {
        return { rows: [{ state: 'pending', source_kind: 'provider_account', source_ref: {} }] };
      }
      if (sql.includes('FROM target_verifications')) {
        return { rows: [{ state: 'provider_verified', source_kind: 'provider_account', source_ref: {}, transitioned_at: new Date('2026-09-02T00:00:00.000Z') }] };
      }
      return { rows: [] };
    },
    release() {},
  };
  return { async connect() { return client; } };
}

describe('target detail bindings and run evidence (Postgres)', () => {
  it('matches the dev JSON bindings, run evidence, and edge request shape', async () => {
    const detail = await createPortalRevampRepository(postgresPool()).getTargetDetailBundle(CTX, 'tgt_web');
    assertTargetDetailBindings(detail);
  });

  it('uses the effective current verification, not a stale provider row, for state and eligibility', async () => {
    const detail = await createPortalRevampRepository(postgresPool()).getTargetDetailBundle(CTX, 'tgt_web');
    assert.equal(detail.verification.state, 'pending');
    assert.equal(detail.verification.history[0].state, 'provider_verified');
  });
});

describe('target detail exposes canonical top-level tags (WAF-CDN-01)', () => {
  const AISTRIP_TAGS = ['env:production', 'domain:aistrip.com', 'cdn', 'waf'];

  it('dev JSON detail target carries the declared tags from metadata', () => {
    seedDevStore();
    const target = getStore().targets.find((t) => t.id === 'tgt_web');
    target.metadata = { tags: AISTRIP_TAGS };
    const detail = getTargetDetail(CTX, 'tgt_web');
    assert.deepEqual(detail.target.tags, AISTRIP_TAGS, 'detail must expose the same tags as the collection');
  });

  it('dev JSON detail target returns an empty tag array (never missing) when untagged', () => {
    seedDevStore();
    const detail = getTargetDetail(CTX, 'tgt_web');
    assert.deepEqual(detail.target.tags, [], 'tags is always present as string[]');
    assert.ok('tags' in detail.target);
  });

  it('Postgres detail bundle carries the declared tags from metadata_json', async () => {
    const pool = {
      async connect() {
        return {
          async query(text, params = []) {
            const sql = String(text);
            if (sql.includes('SELECT * FROM targets WHERE')) {
              return { rows: [{ ...TARGET, metadata_json: { tags: AISTRIP_TAGS }, created_at: new Date('2026-09-01T00:00:00.000Z') }] };
            }
            if (sql.includes('COUNT(*) FILTER')) return { rows: [{ open_count: 0, closed_count: 0 }] };
            if (sql.includes('DISTINCT ON (r.check_id)')) return { rows: [] };
            if (sql.includes('FROM test_runs')) return { rows: [] };
            if (sql.includes('FROM test_policies')) return { rows: [] };
            if (sql.includes('FROM target_verification_current')) {
              return { rows: [{ state: 'dns_verified', source_kind: 'dns_txt', source_ref: {} }] };
            }
            if (sql.includes('FROM target_verifications')) {
              return { rows: [{ state: 'dns_verified', source_kind: 'dns_txt', source_ref: {}, transitioned_at: new Date('2026-09-02T00:00:00.000Z') }] };
            }
            return { rows: [] };
          },
          release() {},
        };
      },
    };
    const detail = await createPortalRevampRepository(pool).getTargetDetailBundle(CTX, 'tgt_web');
    assert.deepEqual(detail.target.tags, AISTRIP_TAGS, 'Postgres detail must match the collection tags');
  });
});

describe('target detail row helpers', () => {
  it('only publishes a last verdict when the verdict record cites evidence', () => {
    assert.equal(evidenceBackedVerdict({ verdict: 'pass', evidence_ids: ['evt_1'] }), 'pass');
    assert.equal(evidenceBackedVerdict({ verdict: 'pass', evidence_ids: [] }), null);
    assert.equal(evidenceBackedVerdict({ verdict: 'pending', evidence_ids: ['evt_1'] }), null);
    assert.equal(evidenceBackedVerdict(null), null);
  });

  it('never falls back from a missing verdict record to run status', () => {
    const row = recentRunRow({ id: 'run_1', status: 'completed', created_at: '2026-09-01T00:00:00.000Z' });
    assert.equal(row.verdict, 'unknown');
    assert.equal(row.status, 'completed');
    assert.deepEqual(row.evidence_ids, []);
    assert.equal(row.completed_at, null);
  });

  it('prefers a target-scoped policy over a group-wide one and marks disabled policies', () => {
    const rows = boundCheckRows(TARGET, [
      { id: 'pol_a', target_group_id: 'tg_web', check_id: RUNNABLE, state: 'disabled', enabled: false },
      { id: 'pol_b', target_group_id: 'tg_web', target_id: 'tgt_web', check_id: RUNNABLE, state: 'active' },
      { id: 'pol_c', target_group_id: 'tg_web', check_id: OTHER_RUNNABLE, state: 'active', enabled: false },
    ]);
    assert.deepEqual(rows.map((row) => [row.check_id, row.policy_id, row.binding_scope, row.policy_state]), [
      [RUNNABLE, 'pol_b', 'target', 'active'],
      [OTHER_RUNNABLE, 'pol_c', 'target_group', 'disabled'],
    ]);
  });
});
