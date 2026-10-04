import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getEvidenceContext, resolveEvidenceContext } from '../../src/services/evidenceContext.mjs';
import { getRunEvents } from '../../src/services/testRuns.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';

const TENANT = 'ten_ctx';

function ctx(role = 'admin') {
  return { tenantId: TENANT, userId: 'usr_ctx', role };
}

function findingSnapshot(overrides = {}) {
  return {
    entry: 'finding',
    tenantId: TENANT,
    ids: { finding_id: 'fnd_open' },
    finding: {
      id: 'fnd_open',
      tenant_id: TENANT,
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      test_run_id: 'run_open',
      verdict_id: 'verdict_open',
      last_verdict_id: null,
      status: 'open',
      notes: 'origin note',
      evidence_ids: ['ev_original'],
      created_at: '2026-10-02T00:00:00.000Z',
    },
    originRun: {
      id: 'run_open',
      tenant_id: TENANT,
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      status: 'verdicted',
      verdict: {
        id: 'verdict_open',
        verdict: 'allowed',
        explanation: 'edge allowed the marker',
        expected_behavior: 'block_at_edge',
        evidence_ids: ['ev_original'],
        created_at: '2026-10-02T00:00:00.000Z',
      },
    },
    laterRuns: [
      {
        id: 'run_other_check',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'other.check',
        status: 'verdicted',
        verdict: {
          id: 'verdict_other',
          verdict: 'blocked',
          evidence_ids: ['ev_other'],
          created_at: '2026-10-05T00:00:00.000Z',
        },
      },
      {
        id: 'run_later',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        status: 'verdicted',
        verdict: {
          id: 'verdict_later',
          verdict: 'blocked',
          evidence_ids: ['ev_later'],
          created_at: '2026-10-04T00:00:00.000Z',
        },
      },
      {
        id: 'run_running',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        status: 'running',
        verdict: {
          id: 'verdict_running',
          verdict: 'blocked',
          evidence_ids: ['ev_running'],
          created_at: '2026-10-06T00:00:00.000Z',
        },
      },
    ],
    primaryIds: ['ev_original'],
    alternativeIds: [],
    evidenceById: new Map([
      ['ev_original', {
        id: 'ev_original',
        tenant_id: TENANT,
        test_run_id: 'run_open',
        metadata: { sha256: 'abc' },
      }],
    ]),
    missingEvidenceIds: [],
    events: [{
      id: 'evt_open',
      tenant_id: TENANT,
      test_run_id: 'run_open',
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      metadata: {
        method: 'GET',
        path: '/health?token=super-secret-query',
        protocol: 'https',
        engine: 'bounded-check',
        max_requests: 1,
        timeout_ms: 1000,
        status_code: 200,
        external_result: 'allowed',
        authorization: 'Bearer abc',
        cookie: 'session=secret-cookie',
        headers: { authorization: 'Bearer abc' },
        body: 'raw-body-secret',
        agent_id: 'agent-should-not-leak',
        query: 'token=super-secret-query',
      },
    }],
    ...overrides,
  };
}

describe('resolveEvidenceContext', () => {
  it('keeps the finding evidence ids and separates a later same-pair result', () => {
    const { status, body } = resolveEvidenceContext(findingSnapshot());
    assert.equal(status, 200);
    assert.equal(body.entry, 'finding');
    assert.deepEqual(body.primary.evidence_ids, ['ev_original']);
    assert.equal(body.primary.verdict_id, 'verdict_open');
    assert.equal(body.primary.test_run_id, 'run_open');
    assert.equal(body.primary.integrity.status, 'recorded_digest');
    assert.equal(body.primary.integrity.verified_at, null);
    assert.equal(body.primary.integrity.method, null);
    assert.equal(body.primary.integrity.refs[0].status, 'recorded_digest');
    assert.equal(body.state, 'ready');
    assert.notEqual(body.latest_same_check.verdict_id, 'verdict_running');
    assert.equal(body.latest_distinct, null);
    assert.equal(body.latest_same_check.verdict_id, 'verdict_later');
    assert.equal(body.latest_same_check.test_run_id, 'run_later');
    assert.deepEqual(body.latest_same_check.evidence_ids, ['ev_later']);
    assert.equal(body.latest_same_check.relationship, 'later_run_same_target_check');
    assert.equal(body.latest_same_check.closes_finding, false);
    assert.equal(body.originating.verdict_id, 'verdict_open');
    assert.equal(body.request_summary.path, '/health');
    assert.equal(body.request_summary.method, 'GET');
    assert.equal(body.response_summary.status_code, 200);
    assert.equal(body.evaluation.confidence, 'external_only');
    assert.equal(body.evaluation.verdict, 'allowed');
    const blob = JSON.stringify(body);
    for (const secret of ['super-secret-query', 'session=secret-cookie', 'raw-body-secret', 'agent-should-not-leak', 'Bearer abc']) {
      assert.equal(blob.includes(secret), false, secret);
    }
    assert.equal(blob.includes('headers'), false);
    assert.equal(blob.includes('authorization'), false);
  });

  it('points latest_distinct at last_verdict_id only when it differs from the origin', () => {
    const { body } = resolveEvidenceContext(findingSnapshot({
      finding: {
        ...findingSnapshot().finding,
        last_verdict_id: 'verdict_later',
      },
    }));
    assert.equal(body.latest_distinct.verdict_id, 'verdict_later');
    assert.deepEqual(body.primary.evidence_ids, ['ev_original']);
    assert.equal(body.latest_distinct.closes_finding, false);
  });

  it('returns no_refs when the finding lists no evidence and partial when an id is missing', () => {
    const empty = resolveEvidenceContext(findingSnapshot({
      finding: { ...findingSnapshot().finding, evidence_ids: [] },
      originRun: {
        ...findingSnapshot().originRun,
        verdict: { ...findingSnapshot().originRun.verdict, evidence_ids: [] },
      },
      primaryIds: [],
      evidenceById: new Map(),
      events: [],
    }));
    assert.equal(empty.body.primary, null);
    assert.equal(empty.body.unavailable_reason, 'no_refs');
    assert.equal(empty.body.state, 'no_refs');
    assert.equal(empty.body.answer.outcome, 'allowed');
    assert.equal(empty.body.request_summary.status, 'not_recorded');

    const partial = resolveEvidenceContext(findingSnapshot({
      missingEvidenceIds: ['ev_original'],
      evidenceById: new Map(),
    }));
    assert.deepEqual(partial.body.primary.evidence_ids, ['ev_original']);
    assert.equal(partial.body.unavailable_reason, 'partial');
    assert.deepEqual(partial.body.missing_evidence_ids, ['ev_original']);
  });

  it('does not borrow waf vendor, cloud, or origin hosting for another family', () => {
    const edge = {
      tenant_id: TENANT,
      target_id: 'tgt_web',
      test_run_id: 'run_fp',
      cdn_status: 'detected',
      cdn_provider: null,
      waf_status: 'detected',
      waf_vendor: 'waf-only-vendor-zz',
      evidence_json: { cloud: null, layers: [{ family: 'waf', provider: 'waf-only-vendor-zz' }] },
      observed_at: '2026-10-03T00:00:00.000Z',
    };
    const cdn = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'cdn' },
      edge,
      events: [],
    });
    assert.equal(cdn.body.subject.provider, null);
    assert.equal(cdn.body.subject.status, 'detected');
    assert.equal(cdn.body.subject.source, 'not_recorded');
    assert.equal(JSON.stringify(cdn.body).includes('waf-only-vendor-zz'), false);

    const dns = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'dns' },
      edge,
      events: [],
    });
    assert.equal(dns.body.subject.status, 'not_recorded');
    assert.equal(dns.body.subject.provider, null);
    assert.equal(dns.body.primary, null);
    assert.equal(dns.body.unavailable_reason, 'no_refs');

    const origin = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'origin_hosting' },
      edge,
      events: [],
    });
    assert.equal(origin.body.subject.status, 'unknown');
    assert.equal(origin.body.subject.reason, 'no_origin_hosting_observation');
    assert.equal(origin.body.subject.provider, null);
  });

  it('uses captured report refs and does not treat a digest as verified custody', () => {
    const { body } = resolveEvidenceContext({
      entry: 'report',
      tenantId: TENANT,
      ids: { report_id: 'rpt_1' },
      report: {
        id: 'rpt_1',
        tenant_id: TENANT,
        title: 'Weekly',
        status: 'ready',
        created_at: '2026-10-01T00:00:00.000Z',
        run_ids: ['run_captured'],
        summary: { as_of: '2026-10-01T00:00:00.000Z', evidence_ids: ['ev_captured'] },
      },
      summary: { as_of: '2026-10-01T00:00:00.000Z', evidence_ids: ['ev_captured'] },
      runIds: ['run_captured'],
      primaryIds: ['ev_captured'],
      evidenceById: new Map([
        ['ev_captured', { id: 'ev_captured', metadata: { sha256: 'digest', verified_at: null } }],
      ]),
      missingEvidenceIds: [],
      events: [],
    });
    assert.equal(body.subject.as_of, '2026-10-01T00:00:00.000Z');
    assert.equal(body.subject.score, null);
    assert.equal(body.subject.factors, null);
    assert.deepEqual(body.subject.run_ids, ['run_captured']);
    assert.equal(body.primary, null);
    const captured = body.alternatives.find((item) => item.evidence_id === 'ev_captured');
    assert.equal(captured.relationship, 'report_snapshot_evidence');
    assert.equal(captured.integrity.status, 'recorded_digest');
    assert.equal(captured.integrity.verified_at, null);
    assert.equal(body.alternatives.some((item) => item.test_run_id === 'run_captured'), true);
    assert.equal(JSON.stringify(body).includes('run_newer'), false);
    assert.equal(body.latest_distinct, null);
  });
});

describe('getEvidenceContext access', () => {
  it('rejects group ids and checks audit permission before lookup', async () => {
    let reads = 0;
    const deps = {
      audit: {
        getAuditEntry() {
          reads += 1;
          throw new Error('lookup');
        },
      },
      persistenceMode: 'postgres',
    };
    const grouped = await getEvidenceContext(ctx('admin'), { entry: 'audit', audit_id: 'aud_1', group_id: 'grp_1' }, deps);
    assert.equal(grouped.status, 400);
    assert.equal(grouped.body.error, 'group_id_not_supported');
    assert.equal(reads, 0);

    const denied = await getEvidenceContext(ctx('viewer'), { entry: 'audit', audit_id: 'aud_1' }, deps);
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'forbidden');
    assert.equal(denied.body.permission, 'audit:read');
    assert.equal(denied.body.state, 'denied');
    assert.equal(reads, 0);

    const engineer = await getEvidenceContext(ctx('engineer'), { entry: 'audit', audit_id: 'aud_1' }, deps);
    assert.equal(engineer.status, 403);
    assert.equal(engineer.body.permission, 'audit:read');
    assert.equal(reads, 0);
  });

  it('returns 404 for a missing tenant record and for another finding artifact', async () => {
    const missing = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_other' }, {
      findings: { getFinding: async () => null },
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.body.error, 'not_found');

    let listed = 0;
    const foreign = await getEvidenceContext(ctx(), {
      entry: 'group_member',
      finding_id: 'fnd_open',
      evidence_id: 'ev_foreign',
    }, {
      findings: {
        getFinding: async () => ({
          id: 'fnd_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          test_run_id: 'run_open',
          verdict_id: 'verdict_open',
          evidence_ids: ['ev_original'],
        }),
      },
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          verdict: { id: 'verdict_open', evidence_ids: ['ev_original'] },
        }),
        listTestRuns() {
          listed += 1;
          return [];
        },
      },
      evidence: { getEvidence: async () => ({ id: 'ev_foreign', tenant_id: TENANT }) },
    });
    assert.equal(foreign.status, 404);
    assert.equal(listed, 0);
  });

  it('does not list other runs for an exact check result', async () => {
    let listed = 0;
    const result = await getEvidenceContext(ctx(), {
      entry: 'check_result',
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      test_run_id: 'run_open',
    }, {
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          status: 'verdicted',
          verdict: { id: 'verdict_open', verdict: 'allowed', evidence_ids: ['ev_original'], created_at: '2026-10-02T00:00:00.000Z' },
        }),
        getRunEvents: async () => [],
        listTestRuns() {
          listed += 1;
          throw new Error('check result must not scan sibling runs');
        },
      },
      evidence: {
        getEvidence: async () => ({
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          metadata: { sha256: 'abc' },
        }),
      },
    });
    assert.equal(result.status, 200);
    assert.equal(result.body.primary.verdict_id, 'verdict_open');
    assert.equal(result.body.latest_distinct, null);
    assert.equal(listed, 0);
  });

  it('maps a read failure to fetch_failed and does not substitute a bad id', async () => {
    const invalid = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'bad id' });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error, 'invalid_id');

    const failed = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, {
      findings: {
        getFinding() {
          throw new Error('database unavailable');
        },
      },
    });
    assert.equal(failed.status, 503);
    assert.equal(failed.body.unavailable_reason, 'fetch_failed');
    assert.equal(failed.body.state, 'unavailable');
  });
});

function scopedEvent(id, metadata, overrides = {}) {
  return {
    id,
    tenant_id: TENANT,
    test_run_id: 'run_open',
    target_id: 'tgt_web',
    check_id: 'app.marker.safe',
    metadata,
    ...overrides,
  };
}

describe('evidence context correctness', () => {
  it('does not treat customer metadata as custody or let one artifact verify another', () => {
    const claimed = resolveEvidenceContext({
      entry: 'artifact',
      tenantId: TENANT,
      artifact: {
        id: 'ev_customer',
        tenant_id: TENANT,
        metadata: { verified_at: '2026-10-04T00:00:00Z', verify_method: 'customer_supplied' },
      },
      events: [],
    });
    assert.equal(claimed.body.primary.integrity.status, 'not_verified');
    assert.equal(claimed.body.primary.integrity.verified_at, null);
    assert.equal(claimed.body.primary.integrity.method, null);

    const hidden = resolveEvidenceContext({
      entry: 'artifact',
      tenantId: TENANT,
      artifact: {
        id: 'ev_hidden',
        tenant_id: TENANT,
        metadata: {
          verified_at: '2026-10-04T00:00:00Z',
          verify_method: 'customer_supplied',
          verification: {
            ok: true,
            method: 'custody_manifest',
            verified_at: '2026-10-04T00:00:00Z',
            covered_refs: ['ev_hidden'],
          },
        },
      },
      events: [],
    });
    assert.equal(hidden.body.primary.integrity.status, 'not_verified');

    const digestAndClaim = resolveEvidenceContext(findingSnapshot({
      evidenceById: new Map([
        ['ev_original', {
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          metadata: { sha256: 'abc', verified_at: '2026-10-04T00:00:00Z', verify_method: 'customer_supplied' },
        }],
      ]),
    }));
    assert.equal(digestAndClaim.body.primary.integrity.status, 'recorded_digest');
    assert.equal(digestAndClaim.body.primary.integrity.verified_at, null);

    const mixed = resolveEvidenceContext(findingSnapshot({
      finding: { ...findingSnapshot().finding, evidence_ids: ['ev_auth', 'ev_customer'] },
      primaryIds: ['ev_auth', 'ev_customer'],
      evidenceById: new Map([
        ['ev_auth', {
          id: 'ev_auth',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          verification: {
            ok: true,
            method: 'custody_manifest',
            verified_at: '2026-10-04T00:00:00.000Z',
            covered_refs: ['ev_auth', 'ev_customer'],
          },
        }],
        ['ev_customer', {
          id: 'ev_customer',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          metadata: { verified_at: '2026-10-04T00:00:00Z', verify_method: 'customer_supplied' },
        }],
      ]),
    }));
    assert.notEqual(mixed.body.primary.integrity.status, 'verified');
    assert.equal(mixed.body.primary.integrity.refs.find((ref) => ref.evidence_id === 'ev_auth').status, 'verified');
    assert.equal(mixed.body.primary.integrity.refs.find((ref) => ref.evidence_id === 'ev_customer').status, 'not_verified');
    assert.equal(mixed.body.primary.integrity.verified_at, null);

    const rejected = resolveEvidenceContext({
      entry: 'artifact',
      tenantId: TENANT,
      artifact: {
        id: 'ev_fail',
        tenant_id: TENANT,
        verification: {
          ok: false,
          method: 'custody_manifest',
          verified_at: '2026-10-04T00:00:00.000Z',
          covered_refs: ['ev_fail'],
        },
      },
      events: [],
    });
    assert.equal(rejected.body.primary.integrity.status, 'not_verified');

    const supplied = resolveEvidenceContext({
      entry: 'artifact',
      tenantId: TENANT,
      artifact: {
        id: 'ev_supplied',
        tenant_id: TENANT,
        verification: {
          ok: true,
          method: 'customer_supplied',
          verified_at: '2026-10-04T00:00:00.000Z',
          covered_refs: ['ev_supplied'],
        },
      },
      events: [],
    });
    assert.equal(supplied.body.primary.integrity.status, 'not_verified');

    const otherRef = resolveEvidenceContext({
      entry: 'artifact',
      tenantId: TENANT,
      artifact: {
        id: 'ev_row',
        tenant_id: TENANT,
        verification: {
          ok: true,
          method: 'custody_manifest',
          verified_at: '2026-10-04T00:00:00.000Z',
          covered_refs: ['ev_other'],
        },
      },
      events: [],
    });
    assert.equal(otherRef.body.primary.integrity.status, 'not_recorded');
  });

  it('rejects cross-target, unbound, and conflicting records instead of borrowing them', async () => {
    const secret = 'other-target-secret-zz';
    const cross = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, {
      findings: {
        getFinding: async () => ({
          id: 'fnd_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          test_run_id: 'run_open',
          verdict_id: 'verdict_open',
          status: 'open',
          evidence_ids: ['ev_original'],
        }),
      },
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_other',
          check_id: 'app.marker.safe',
          status: 'verdicted',
          verdict: {
            id: 'verdict_open',
            verdict: 'allowed',
            explanation: secret,
            evidence_ids: ['ev_original'],
          },
        }),
        getRunEvents: async () => [scopedEvent('evt_other', { method: 'DELETE', path: '/other-scope' }, { target_id: 'tgt_other' })],
        listTestRuns: async () => [],
      },
      evidence: {
        getEvidence: async () => ({
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          label: secret,
          metadata: { sha256: 'other-digest' },
        }),
      },
    });
    assert.equal(cross.status, 200);
    assert.equal(cross.body.state, 'partial');
    assert.equal(cross.body.evaluation.status, 'not_recorded');
    assert.equal(cross.body.request_summary.status, 'not_recorded');
    assert.equal(cross.body.primary.integrity.status, 'not_recorded');
    assert.equal(cross.body.alternatives.some((item) => item.relationship === 'scope_conflict'), true);
    assert.equal(JSON.stringify(cross.body).includes(secret), false);
    assert.equal(JSON.stringify(cross.body).includes('DELETE'), false);

    const unbound = resolveEvidenceContext(findingSnapshot({
      originRun: {
        id: 'run_open',
        tenant_id: TENANT,
        check_id: 'app.marker.safe',
        status: 'verdicted',
        verdict: { id: 'verdict_open', verdict: 'allowed', explanation: secret, evidence_ids: ['ev_original'] },
      },
    }));
    assert.equal(unbound.body.state, 'partial');
    assert.equal(unbound.body.evaluation.status, 'not_recorded');
    assert.equal(JSON.stringify(unbound.body).includes(secret), false);

    const foreignRow = resolveEvidenceContext(findingSnapshot({
      evidenceById: new Map([
        ['ev_original', {
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_elsewhere',
          label: secret,
          metadata: { sha256: 'elsewhere' },
        }],
      ]),
    }));
    assert.equal(foreignRow.body.primary.integrity.status, 'not_recorded');
    assert.equal(foreignRow.body.alternatives.some((item) => item.relationship === 'scope_conflict'), true);
    assert.equal(JSON.stringify(foreignRow.body).includes(secret), false);
  });

  it('does not select a later run that is unbound, running, cancelled, or not evidence-backed', () => {
    const base = findingSnapshot();
    const rejected = (run) => resolveEvidenceContext(findingSnapshot({
      finding: { ...base.finding, last_verdict_id: run.verdict.id },
      laterRuns: [run],
    }));
    const cases = [
      { id: 'run_missing_target', tenant_id: TENANT, check_id: 'app.marker.safe', status: 'verdicted' },
      { id: 'run_running_late', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'running' },
      { id: 'run_cancelled', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'cancelled' },
      { id: 'run_empty', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted', evidence_ids: [] },
    ];
    for (const item of cases) {
      const run = {
        id: item.id,
        tenant_id: item.tenant_id,
        target_id: item.target_id,
        check_id: item.check_id,
        status: item.status,
        verdict: {
          id: `verdict_${item.id}`,
          verdict: 'blocked',
          evidence_ids: item.evidence_ids ?? ['ev_late'],
          created_at: '2026-10-09T00:00:00.000Z',
        },
      };
      const body = rejected(run).body;
      assert.equal(body.latest_same_check, null, item.id);
      assert.equal(body.latest_distinct, null, item.id);
      assert.equal(body.latest_same_check?.closes_finding, undefined);
    }
  });

  it('keeps report snapshot refs together and does not invent a primary or borrow live fields', async () => {
    let runs = 0;
    const loaded = await getEvidenceContext(ctx(), { entry: 'report', report_id: 'rpt_1' }, {
      reports: {
        getReport: async () => ({
          id: 'rpt_1',
          tenant_id: TENANT,
          title: 'Weekly',
          status: 'ready',
          created_at: '2026-09-01T00:00:00.000Z',
          run_ids: ['run_a', 'run_b'],
          summary: {
            as_of: '2026-10-01T00:00:00.000Z',
            readiness_score: 41,
            readiness_factors: ['external_only'],
            evidence_ids: ['ev_a', 'ev_b'],
          },
        }),
      },
      testRuns: {
        getTestRun() {
          runs += 1;
          throw new Error('report must not read live runs');
        },
      },
      evidence: {
        getEvidence: async (ctx, id) => ({
          id,
          tenant_id: TENANT,
          metadata: { sha256: `digest-${id}`, verified_at: '2026-10-04T00:00:00Z', verify_method: 'customer_supplied' },
        }),
      },
    });
    assert.equal(loaded.status, 200);
    assert.equal(runs, 0);
    assert.equal(loaded.body.primary, null);
    assert.equal(loaded.body.subject.as_of, '2026-10-01T00:00:00.000Z');
    assert.equal(loaded.body.subject.score, 41);
    assert.deepEqual(loaded.body.subject.factors, ['external_only']);
    assert.deepEqual(loaded.body.subject.run_ids, ['run_a', 'run_b']);
    assert.deepEqual(
      loaded.body.alternatives.filter((item) => item.relationship === 'report_snapshot_run').map((item) => item.test_run_id),
      ['run_a', 'run_b'],
    );
    assert.equal(loaded.body.alternatives.find((item) => item.evidence_id === 'ev_a').integrity.status, 'recorded_digest');
    assert.equal(JSON.stringify(loaded.body).includes('2026-09-01'), false);

    const named = resolveEvidenceContext({
      entry: 'report',
      tenantId: TENANT,
      report: { id: 'rpt_1', tenant_id: TENANT, status: 'ready', created_at: '2026-09-01T00:00:00.000Z' },
      summary: { primary_test_run_id: 'run_b', evidence_ids: ['ev_a'], readiness_score: 7 },
      runIds: ['run_a', 'run_b'],
      primaryIds: ['ev_a'],
      evidenceById: new Map([['ev_a', { id: 'ev_a', metadata: { sha256: 'aaa' } }]]),
      missingEvidenceIds: [],
      events: [],
    });
    assert.equal(named.body.primary.test_run_id, 'run_b');
    assert.deepEqual(named.body.primary.evidence_ids, []);
    assert.equal(named.body.subject.score, 7);
    assert.equal(named.body.subject.as_of, null);
  });

  it('exposes family proof and keeps other-family signals off the payload', () => {
    const edge = {
      tenant_id: TENANT,
      target_id: 'tgt_web',
      test_run_id: 'run_fp',
      cdn_status: 'detected',
      cdn_providers: ['cdn-a', 'cdn-b'],
      cdn_type: 'cname_suffix',
      waf_status: 'detected',
      waf_vendor: 'waf-only-vendor-zz',
      confidence: 0.8,
      corpus_version: 'corpus-9',
      conflicting_vendor_signals: true,
      observed_at: '2026-10-03T00:00:00.000Z',
      evidence_json: {
        conflicting_provider_signals: true,
        cname_cdn_matches: [
          { family: 'cdn', provider: 'cdn-a', suffix: 'a.cdn.test' },
          { family: 'cdn', provider: 'cdn-b', suffix: 'b.cdn.test' },
        ],
        dns_resolved_ips: ['203.0.113.10'],
        vendor_matches: [{ vendor: 'waf-only-vendor-zz', name: 'waf-fingerprint', matched_signals: [{ signal: 'server_header' }] }],
        headers: { server: 'secret-header' },
        layers: [
          { family: 'cdn', provider: 'cdn-a', sources: ['cname_suffix'], confidence: 0.4 },
          { family: 'cdn', provider: 'cdn-b', sources: ['address_range'], confidence: 0.6 },
          { family: 'waf', provider: 'waf-only-vendor-zz', sources: ['response_fingerprint'] },
        ],
      },
    };
    const cdn = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'cdn' },
      edge,
      events: [],
    });
    assert.equal(cdn.body.subject.provider, null);
    assert.equal(cdn.body.subject.conflict, true);
    assert.equal(cdn.body.subject.corpus, 'corpus-9');
    assert.deepEqual(cdn.body.subject.proof.cnames, ['a.cdn.test', 'b.cdn.test']);
    assert.deepEqual(cdn.body.subject.proof.addresses, ['203.0.113.10']);
    assert.equal(cdn.body.subject.proof.methods.includes('address_range'), true);
    assert.equal(cdn.body.primary.test_run_id, 'run_fp');
    assert.equal(cdn.body.evaluation.status, 'recorded');
    assert.deepEqual(
      cdn.body.alternatives.filter((item) => item.relationship === 'provider_layer').map((item) => item.provider).sort(),
      ['cdn-a', 'cdn-b'],
    );
    const cdnBlob = JSON.stringify(cdn.body);
    for (const leaked of ['waf-only-vendor-zz', 'waf-fingerprint', 'server_header', 'secret-header', 'response_fingerprint']) {
      assert.equal(cdnBlob.includes(leaked), false, leaked);
    }

    const waf = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'waf' },
      edge,
      events: [],
    });
    assert.equal(waf.body.subject.provider, 'waf-only-vendor-zz');
    assert.equal(waf.body.subject.proof.matched_signals.includes('server_header'), true);
    assert.equal(waf.body.subject.proof.fingerprints.includes('waf-fingerprint'), true);
    assert.equal(JSON.stringify(waf.body).includes('a.cdn.test'), false);
    assert.equal(JSON.stringify(waf.body).includes('203.0.113.10'), false);

    const methodOnly = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'cdn' },
      edge: { tenant_id: TENANT, cdn_status: 'detected', cdn_type: 'cname_suffix', test_run_id: 'run_fp' },
      events: [],
    });
    assert.equal(methodOnly.body.primary, null);
    assert.equal(methodOnly.body.unavailable_reason, 'no_refs');
    assert.equal(methodOnly.body.evaluation.status, 'not_recorded');
    assert.deepEqual(methodOnly.body.subject.proof.methods, ['cname_suffix']);
    assert.deepEqual(methodOnly.body.subject.proof.cnames, []);
  });

  it('drops credential header values and untyped addresses from provider proof', () => {
    const edge = {
      tenant_id: TENANT,
      target_id: 'tgt_web',
      test_run_id: 'run_fp',
      cdn_status: 'detected',
      cdn_providers: ['cdn-a'],
      waf_status: 'detected',
      waf_vendor: 'waf-only-vendor-zz',
      evidence_json: {
        cname_cdn_matches: [
          { family: 'cdn', provider: 'cdn-a', suffix: 'a.cdn.test' },
          { family: 'cdn', provider: 'cdn-a', suffix: 'b.cdn.test' },
          { family: 'cdn', provider: 'cdn-a', item_type: 'ip', suffix: 'typed-wrong.cdn.test', value: '203.0.113.50' },
        ],
        dns_resolved_ips: ['203.0.113.10', 'not-an-ip', 'Cookie: session=raw-cookie-zz'],
        dns_cname_chain: ['not a host', 'Cookie: session=raw-cookie-zz'],
        address_matches: [{ family: 'cdn', item_type: 'cname', address: '198.51.100.20', value: 'malformed.example' }],
        vendor_matches: [{
          vendor: 'waf-only-vendor-zz',
          name: 'waf-fingerprint',
          matched_signals: [
            'Cookie: session=raw-cookie-zz',
            'Authorization: Basic dXNlcjpwYXNz',
            { signal: 'server_header', value: 'Set-Cookie: sid=raw-set-cookie-zz' },
          ],
        }],
        layers: [{
          family: 'waf',
          provider: 'waf-only-vendor-zz',
          sources: ['cname_suffix'],
          matched_signals: ['Set-Cookie: sid=raw-set-cookie-zz', 'Basic dXNlcjpwYXNz'],
        }],
        wafw00f: { firewall: 'waf-fingerprint' },
      },
    };
    const cdn = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'cdn' },
      edge,
      events: [],
    });
    assert.deepEqual(cdn.body.subject.proof.cnames, ['a.cdn.test', 'b.cdn.test']);
    assert.deepEqual(cdn.body.subject.proof.addresses, ['203.0.113.10']);
    const waf = resolveEvidenceContext({
      entry: 'provider',
      tenantId: TENANT,
      ids: { target_id: 'tgt_web', family: 'waf' },
      edge,
      events: [],
    });
    assert.equal(waf.body.subject.proof.fingerprints.includes('waf-fingerprint'), true);
    assert.equal(waf.body.subject.proof.matched_signals.includes('server_header'), true);
    assert.equal(waf.body.subject.proof.fingerprints.includes('waf-only-vendor-zz'), false);
    const blob = JSON.stringify({ cdn: cdn.body, waf: waf.body });
    for (const leaked of [
      'raw-cookie-zz',
      'raw-set-cookie-zz',
      'dXNlcjpwYXNz',
      'not-an-ip',
      'typed-wrong.cdn.test',
      '198.51.100.20',
      'malformed.example',
      'Basic ',
      'Cookie:',
      'Set-Cookie:',
      'Authorization:',
    ]) {
      assert.equal(blob.includes(leaked), false, leaked);
    }
  });

  it('uses one correlated event and does not merge operation fields across events', () => {
    const events = [
      scopedEvent('evt_get', { method: 'GET', path: '/health?token=super-secret-query', status_code: 200, external_result: 'allowed' }),
      scopedEvent('evt_post', { method: 'POST', path: '/admin', status_code: 500, external_result: 'blocked' }),
    ];
    const merged = resolveEvidenceContext(findingSnapshot({
      events,
      evidenceById: new Map([
        ['ev_original', { id: 'ev_original', tenant_id: TENANT, test_run_id: 'run_open', metadata: { sha256: 'abc' } }],
      ]),
    }));
    assert.equal(merged.body.request_summary.status, 'not_recorded');
    assert.equal(merged.body.response_summary.status, 'not_recorded');
    assert.equal(merged.body.state, 'partial');
    assert.deepEqual(
      merged.body.alternatives.filter((item) => item.relationship === 'unmatched_operation').map((item) => item.event_id).sort(),
      ['evt_get', 'evt_post'],
    );

    const selected = resolveEvidenceContext(findingSnapshot({
      events,
      evidenceById: new Map([
        ['ev_original', {
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          related_event_id: 'evt_post',
          metadata: { sha256: 'abc' },
        }],
      ]),
    }));
    assert.equal(selected.body.request_summary.method, 'POST');
    assert.equal(selected.body.request_summary.path, '/admin');
    assert.equal(selected.body.response_summary.status_code, 500);
    assert.equal(selected.body.response_summary.external_result, 'blocked');
    assert.equal(selected.body.request_summary.event_id, 'evt_post');
    assert.equal(JSON.stringify(selected.body).includes('/health'), false);
    assert.equal(selected.body.alternatives.some((item) => item.event_id === 'evt_get'), true);
  });

  it('keeps multiple referenced operations separate and does not call a missing ref not_recorded', () => {
    const events = [
      scopedEvent('evt_get', { method: 'GET', path: '/health', requests_sent: 0, source_kind: 'manual_declaration' }),
      scopedEvent('evt_post', { method: 'POST', path: '/admin', status_code: 500, requests_simulated: 2, provenance_kind: 'internal_simulation' }),
    ];
    const multiple = resolveEvidenceContext(findingSnapshot({
      events,
      primaryIds: ['ev_get', 'ev_post'],
      finding: { ...findingSnapshot().finding, evidence_ids: ['ev_get', 'ev_post'] },
      evidenceById: new Map([
        ['ev_get', { id: 'ev_get', tenant_id: TENANT, test_run_id: 'run_open', related_event_id: 'evt_get', metadata: { sha256: 'a' } }],
        ['ev_post', { id: 'ev_post', tenant_id: TENANT, test_run_id: 'run_open', metadata: { sha256: 'b', probe_event_id: 'evt_post' } }],
      ]),
    }));
    assert.equal(multiple.body.request_summary.status, 'referenced');
    assert.equal(multiple.body.request_summary.ref_status, 'multiple');
    assert.equal(multiple.body.request_summary.method, undefined);
    assert.equal(multiple.body.request_summary.path, undefined);
    const correlated = multiple.body.alternatives.filter((item) => item.relationship === 'correlated_operation');
    assert.deepEqual(correlated.map((item) => item.event_id).sort(), ['evt_get', 'evt_post']);
    const getOp = correlated.find((item) => item.event_id === 'evt_get');
    const postOp = correlated.find((item) => item.event_id === 'evt_post');
    assert.equal(getOp.request_summary.method, 'GET');
    assert.equal(getOp.request_summary.path, '/health');
    assert.equal(getOp.request_summary.request_count.status, 'recorded');
    assert.equal(getOp.request_summary.request_count.requests_sent, 0);
    assert.equal(getOp.request_summary.request_count.requests_sent_source, 'metadata.requests_sent');
    assert.equal(getOp.request_summary.provenance.kind, 'manual_declaration');
    assert.equal(getOp.request_summary.provenance.source_field, 'metadata.source_kind');
    assert.equal(getOp.request_summary.provenance.live_external, false);
    assert.equal(postOp.request_summary.method, 'POST');
    assert.equal(postOp.request_summary.request_count.requests_simulated, 2);
    assert.equal(postOp.request_summary.request_count.requests_sent, undefined);
    assert.equal(postOp.request_summary.provenance.kind, 'internal_simulation');
    assert.equal(postOp.request_summary.provenance.source_field, 'metadata.provenance_kind');
    assert.equal(postOp.request_summary.provenance.live_external, false);
    assert.equal(postOp.response_summary.status_code, 500);

    const missing = resolveEvidenceContext(findingSnapshot({
      events: [scopedEvent('evt_get', { method: 'GET', path: '/health' })],
      evidenceById: new Map([
        ['ev_original', {
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          related_event_id: 'evt_foreign',
          metadata: { sha256: 'abc' },
        }],
      ]),
    }));
    assert.equal(missing.body.request_summary.status, 'referenced');
    assert.equal(missing.body.request_summary.ref_status, 'missing');
    assert.equal(missing.body.request_summary.event_id, 'evt_foreign');
    assert.equal(missing.body.request_summary.path, undefined);
    assert.equal(JSON.stringify(missing.body).includes('/health'), false);

    const foreign = resolveEvidenceContext(findingSnapshot({
      events: [
        scopedEvent('evt_get', { method: 'GET', path: '/health' }),
        scopedEvent('evt_foreign', { method: 'GET', path: '/foreign-secret-zz' }, { check_id: 'other.check' }),
      ],
      evidenceById: new Map([
        ['ev_original', {
          id: 'ev_original',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          related_event_id: 'evt_foreign',
          metadata: { sha256: 'abc' },
        }],
      ]),
    }));
    assert.equal(foreign.body.request_summary.status, 'referenced');
    assert.equal(foreign.body.request_summary.ref_status, 'scope_conflict');
    assert.equal(foreign.body.request_summary.path, undefined);
    const foreignBlob = JSON.stringify(foreign.body);
    assert.equal(foreignBlob.includes('/health'), false);
    assert.equal(foreignBlob.includes('/foreign-secret-zz'), false);
    assert.notEqual(foreign.body.request_summary.status, 'not_recorded');
    assert.notEqual(missing.body.request_summary.status, 'not_recorded');
  });

  it('uses the immutable run expected behavior only when the verdict omits it', () => {
    const withVerdict = resolveEvidenceContext(findingSnapshot({
      finding: { ...findingSnapshot().finding, expected_behavior: 'current-target-behavior' },
      originRun: { ...findingSnapshot().originRun, expected_behavior: 'immutable-run-behavior' },
    }));
    assert.equal(withVerdict.body.answer.expected_behavior, 'block_at_edge');
    assert.equal(withVerdict.body.answer.expected_behavior_source, 'verdict.expected_behavior');
    assert.equal(withVerdict.body.evaluation.expected_behavior, 'block_at_edge');
    assert.equal(withVerdict.body.evaluation.expected_behavior_source, 'verdict.expected_behavior');
    assert.equal(withVerdict.body.evaluation.confidence, 'external_only');

    const origin = findingSnapshot().originRun;
    const verdict = { ...origin.verdict };
    delete verdict.expected_behavior;
    const fromRun = resolveEvidenceContext(findingSnapshot({
      finding: { ...findingSnapshot().finding, expected_behavior: 'current-target-behavior' },
      originRun: { ...origin, expected_behavior: 'immutable-run-behavior', verdict },
    }));
    assert.equal(fromRun.body.answer.expected_behavior, 'immutable-run-behavior');
    assert.equal(fromRun.body.answer.expected_behavior_source, 'run.expected_behavior');
    assert.equal(fromRun.body.evaluation.expected_behavior_source, 'run.expected_behavior');
    assert.equal(JSON.stringify(fromRun.body).includes('current-target-behavior'), false);

    const neither = resolveEvidenceContext(findingSnapshot({
      finding: { ...findingSnapshot().finding, expected_behavior: 'current-target-behavior' },
      originRun: { ...origin, verdict },
    }));
    assert.equal(neither.body.answer.expected_behavior, null);
    assert.equal(neither.body.answer.expected_behavior_source, null);
    assert.equal(JSON.stringify(neither.body).includes('current-target-behavior'), false);

    const manual = resolveEvidenceContext(findingSnapshot({
      events: [scopedEvent('evt_open', { method: 'GET', path: '/declared', manual_source: 'customer_note', requests_sent: '2' })],
    }));
    assert.equal(manual.body.request_summary.request_count.status, 'not_recorded');
    assert.equal(manual.body.request_summary.request_count.requests_sent, undefined);
    assert.equal(manual.body.request_summary.provenance.kind, 'customer_note');
    assert.equal(manual.body.request_summary.provenance.source_field, 'metadata.manual_source');
    assert.equal(manual.body.request_summary.provenance.live_external, false);
    assert.equal(manual.body.evaluation.confidence, 'external_only');
  });

  it('loads a referenced event past the history cap and does not fall back when that read fails', async () => {
    const events = Array.from({ length: 27 }, (_, index) => ({
      id: index === 26 ? 'evt_extra_25' : `evt_${index}`,
      tenant_id: TENANT,
      test_run_id: 'run_open',
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      metadata: index === 26
        ? {
          method: 'HEAD',
          path: '/primary-last',
          requests_simulated: 2,
          provenance_kind: 'internal_simulation',
          note: 'omitted-event-token-zz',
        }
        : { method: 'GET', path: index === 0 ? '/first-window-only' : '/window-fill' },
    }));
    const calls = [];
    const loaded = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, {
      findings: {
        getFinding: async () => ({
          id: 'fnd_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          test_run_id: 'run_open',
          verdict_id: 'verdict_open',
          status: 'open',
          evidence_ids: ['ev_late'],
        }),
      },
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          status: 'verdicted',
          verdict: { id: 'verdict_open', verdict: 'allowed', evidence_ids: ['ev_late'], explanation: 'late' },
        }),
        getRunEvents: async (_ctx, id, options = {}) => {
          calls.push({ id, ...options });
          if (Array.isArray(options.ids)) {
            return events.filter((event) => options.ids.includes(event.id)
              && event.target_id === options.target_id
              && event.check_id === options.check_id);
          }
          const slice = events.slice(0, options.limit ?? events.length);
          if (options.limit != null) Object.defineProperty(slice, 'sourceCount', { value: events.length });
          return slice;
        },
        listTestRuns: async () => [],
      },
      evidence: {
        getEvidence: async () => ({
          id: 'ev_late',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          metadata: { sha256: 'late', probe_event_id: 'evt_extra_25' },
        }),
      },
    });
    assert.equal(calls.length, 2);
    assert.equal(calls[0].limit, 21);
    assert.equal(calls[0].ids, undefined);
    assert.deepEqual(calls[1].ids, ['evt_extra_25']);
    assert.equal(calls[1].limit, undefined);
    assert.equal(calls[1].target_id, 'tgt_web');
    assert.equal(calls[1].check_id, 'app.marker.safe');
    assert.equal(loaded.status, 200);
    assert.equal(loaded.body.request_summary.event_id, 'evt_extra_25');
    assert.equal(loaded.body.request_summary.method, 'HEAD');
    assert.equal(loaded.body.request_summary.path, '/primary-last');
    assert.equal(loaded.body.request_summary.request_count.requests_simulated, 2);
    assert.equal(loaded.body.request_summary.request_count.requests_sent, undefined);
    assert.equal(loaded.body.request_summary.provenance.kind, 'internal_simulation');
    assert.equal(loaded.body.request_summary.provenance.source_field, 'metadata.provenance_kind');
    assert.equal(loaded.body.request_summary.provenance.live_external, false);
    assert.equal(loaded.body.evaluation.confidence, 'external_only');
    assert.equal(loaded.body.truncation.events.truncated, true);
    assert.equal(loaded.body.truncation.events.returned, 20);
    assert.equal(loaded.body.truncation.events.limit, 20);
    assert.deepEqual(loaded.body.truncation.events.referenced_event_ids, ['evt_extra_25']);
    assert.deepEqual(loaded.body.truncation.events.referenced_loaded, ['evt_extra_25']);
    assert.deepEqual(loaded.body.truncation.events.referenced_missing, []);
    const blob = JSON.stringify(loaded.body);
    assert.equal(blob.includes('/first-window-only'), false);
    assert.equal(blob.includes('omitted-event-token-zz'), false);

    const failed = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, {
      findings: {
        getFinding: async () => ({
          id: 'fnd_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          test_run_id: 'run_open',
          verdict_id: 'verdict_open',
          status: 'open',
          evidence_ids: ['ev_late'],
        }),
      },
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          status: 'verdicted',
          verdict: { id: 'verdict_open', verdict: 'allowed', evidence_ids: ['ev_late'] },
        }),
        getRunEvents: async (_ctx, _id, options = {}) => {
          if (Array.isArray(options.ids)) throw new Error('transient read');
          return [scopedEvent('evt_0', { method: 'GET', path: '/fallback-secret-zz', note: 'first-event-secret-zz' })];
        },
        listTestRuns: async () => [],
      },
      evidence: {
        getEvidence: async () => ({
          id: 'ev_late',
          tenant_id: TENANT,
          test_run_id: 'run_open',
          related_event_id: 'evt_extra_25',
          metadata: { sha256: 'late' },
        }),
      },
    });
    assert.equal(failed.status, 503);
    assert.equal(failed.body.unavailable_reason, 'fetch_failed');
    assert.equal(failed.body.state, 'unavailable');
    const failedBlob = JSON.stringify(failed.body);
    assert.equal(failedBlob.includes('/fallback-secret-zz'), false);
    assert.equal(failedBlob.includes('first-event-secret-zz'), false);
    assert.equal(failedBlob.includes('GET'), false);
  });

  it('fails closed in postgres mode and bounds getRunEvents', async () => {
    resetStoreForTests({
      findings: [{
        id: 'fnd_open',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        test_run_id: 'run_open',
        verdict_id: 'verdict_open',
        status: 'open',
        evidence_ids: ['ev_original'],
        notes: 'dev-store-only-secret-note',
      }],
      testRuns: [{ id: 'run_open', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted' }],
      verdicts: [{ id: 'verdict_open', tenant_id: TENANT, test_run_id: 'run_open', verdict: 'allowed', explanation: 'dev-store-only-secret-note', evidence_ids: ['ev_original'] }],
      evidenceVault: [{ id: 'ev_original', tenant_id: TENANT, test_run_id: 'run_open', metadata: { sha256: 'abc' } }],
      auditLog: [{ id: 'aud_ctx', tenant_id: TENANT, action: 'dev-audit-should-not-leak', resource_type: 'finding', resource_id: 'fnd_open' }],
      targetEdgeDetections: [{ tenant_id: TENANT, target_id: 'tgt_web', waf_vendor: 'dev-edge-should-not-leak' }],
      events: [],
    });
    const missing = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, { persistenceMode: 'postgres' });
    assert.equal(missing.status, 503);
    assert.equal(missing.body.unavailable_reason, 'fetch_failed');
    assert.equal(JSON.stringify(missing.body).includes('dev-store-only-secret-note'), false);

    const auditMiss = await getEvidenceContext(ctx(), { entry: 'audit', audit_id: 'aud_ctx' }, { persistenceMode: 'postgres' });
    assert.equal(auditMiss.status, 503);
    assert.equal(JSON.stringify(auditMiss.body).includes('dev-audit-should-not-leak'), false);

    const edgeMiss = await getEvidenceContext(ctx(), { entry: 'provider', target_id: 'tgt_web', family: 'cdn' }, {
      persistenceMode: 'postgres',
      targetDetail: { getTargetDetail: async () => ({ target: { id: 'tgt_web', tenant_id: TENANT } }) },
      evidence: { getEvidence: async () => null },
    });
    assert.equal(edgeMiss.status, 503);
    assert.equal(JSON.stringify(edgeMiss.body).includes('dev-edge-should-not-leak'), false);

    const events = Array.from({ length: 25 }, (_, index) => ({
      id: `evt_${index}`,
      tenant_id: TENANT,
      test_run_id: 'run_open',
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      metadata: { method: index === 24 ? 'omitted-event-token-zz' : 'GET' },
    }));
    events.push({
      id: 'evt_other_run',
      tenant_id: TENANT,
      test_run_id: 'run_other',
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      metadata: { method: 'PUT' },
    });
    resetStoreForTests({
      testRuns: [
        { id: 'run_open', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted' },
        { id: 'run_other', tenant_id: TENANT, target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted' },
      ],
      events,
    });
    assert.equal(getRunEvents(ctx(), 'run_open').length, 25);
    const bounded = getRunEvents(ctx(), 'run_open', { limit: 21 });
    assert.equal(bounded.length, 21);
    assert.equal(bounded.sourceCount, 25);
    assert.equal(JSON.stringify(bounded).includes('omitted-event-token-zz'), false);
    const exact = getRunEvents(ctx(), 'run_open', {
      ids: ['evt_24', 'evt_other_run'],
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
    });
    assert.equal(exact.length, 1);
    assert.equal(exact[0].id, 'evt_24');
    assert.equal(exact.sourceCount, undefined);
    assert.deepEqual(getRunEvents(ctx(), 'run_open', { ids: ['evt_24'], target_id: 'tgt_other', check_id: 'app.marker.safe' }), []);
    assert.deepEqual(getRunEvents(ctx(), 'run_open', { ids: [] }), []);
    const cappedIds = Array.from({ length: 32 }, (_, index) => `missing_${index}`);
    cappedIds.push('evt_24');
    assert.deepEqual(getRunEvents(ctx(), 'run_open', { ids: cappedIds }), []);

    const evidenceIds = Array.from({ length: 33 }, (_, index) => `ev_${index}`);
    let evidenceReads = 0;
    const truncated = await getEvidenceContext(ctx(), { entry: 'finding', finding_id: 'fnd_open' }, {
      findings: {
        getFinding: async () => ({
          id: 'fnd_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          test_run_id: 'run_open',
          verdict_id: 'verdict_open',
          status: 'open',
          evidence_ids: evidenceIds,
        }),
      },
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open',
          tenant_id: TENANT,
          target_id: 'tgt_web',
          check_id: 'app.marker.safe',
          status: 'verdicted',
          verdict: { id: 'verdict_open', verdict: 'allowed', evidence_ids: evidenceIds },
        }),
        getRunEvents: async () => [],
        listTestRuns: async () => [],
      },
      evidence: {
        getEvidence: async (_ctx, id) => {
          evidenceReads += 1;
          return { id, tenant_id: TENANT, test_run_id: 'run_open', metadata: { sha256: 'abc' } };
        },
      },
    });
    assert.equal(truncated.status, 200);
    assert.equal(truncated.body.truncation.evidence_refs.source_count, 33);
    assert.equal(truncated.body.truncation.evidence_refs.returned, 32);
    assert.equal(truncated.body.truncation.evidence_refs.truncated, true);
    assert.equal(truncated.body.state, 'partial');
    assert.equal(truncated.body.missing_evidence_ids, undefined);
    assert.equal(evidenceReads, 32);

    const auditHit = await getEvidenceContext(ctx(), { entry: 'audit', audit_id: 'aud_ctx' }, {
      persistenceMode: 'postgres',
      audit: {
        getAuditEntry: async () => ({
          id: 'aud_ctx',
          tenant_id: TENANT,
          action: 'finding.created',
          resource_type: 'finding',
          resource_id: 'fnd_open',
        }),
      },
    });
    assert.equal(auditHit.status, 200);
    assert.equal(auditHit.body.subject.action, 'finding.created');
    assert.equal(JSON.stringify(auditHit.body).includes('dev-audit-should-not-leak'), false);

    let seen = null;
    const repositories = {
      validationEvidence: Object.fromEntries(VALIDATION_EVIDENCE_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      audit: Object.fromEntries(VALIDATION_AUDIT_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      coreCatalog: Object.fromEntries(VALIDATION_CORE_CATALOG_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      probeJobs: Object.fromEntries(VALIDATION_PROBE_JOB_REPOSITORY_METHODS.map((name) => [name, async () => null])),
      killSwitch: Object.fromEntries(VALIDATION_KILL_SWITCH_REPOSITORY_METHODS.map((name) => [name, async () => null])),
    };
    repositories.validationEvidence.getTestRun = async () => ({ id: 'run_open' });
    repositories.validationEvidence.listRunEvents = async (_ctx, id, options) => {
      seen = { id, options };
      return [];
    };
    const services = createPostgresValidationServices(repositories);
    await services.testRuns.getRunEvents(ctx(), 'run_open', { limit: 21 });
    assert.equal(seen.id, 'run_open');
    assert.equal(seen.options.limit, 21);
    await services.testRuns.getRunEvents(ctx(), 'run_open');
    assert.equal(seen.options.limit, undefined);
    await services.testRuns.getRunEvents(ctx(), 'run_open', {
      ids: ['evt_extra_25'],
      target_id: 'tgt_web',
      check_id: 'app.marker.safe',
      limit: 21,
    });
    assert.deepEqual(seen.options.ids, ['evt_extra_25']);
    assert.equal(seen.options.target_id, 'tgt_web');
    assert.equal(seen.options.check_id, 'app.marker.safe');
    assert.equal(seen.options.limit, undefined);
  });
});
