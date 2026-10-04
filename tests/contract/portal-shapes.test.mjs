import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import {
  EVIDENCE_SHAPE,
  FINDING_LINEAGE_SHAPE,
  TARGET_DETAIL_SHAPE,
  validateListEnvelope,
  validateShape,
  VERIFICATION_LADDER_SHAPE,
  WAF_SUMMARY_SHAPE,
} from '../helpers/portal-schema.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';
import { seedPortalEmpty, PORTAL_EMPTY_IDS } from '../fixtures/portal-empty/seed.mjs';

let baseUrl;
let server;
let baselineStore;

before(() => {
  process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
  const store = seedPortalBaseline();
  baselineStore = store;
  store.targetEdgeDetections = [{
    id: 'ted_contract_checkout',
    tenant_id: PORTAL_BASELINE_IDS.tenantId,
    target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
    target_id: PORTAL_BASELINE_IDS.targetId,
    test_run_id: PORTAL_BASELINE_IDS.readinessRunId,
    status: 'detected',
    reason: null,
    waf_status: 'detected',
    waf_vendor: 'cloudflare',
    waf_type: 'response_fingerprint',
    waf_providers: ['cloudflare'],
    cdn_status: 'detected',
    cdn_provider: 'cloudfront',
    cdn_type: 'cname_suffix',
    cdn_providers: ['cloudfront'],
    confidence: 0.94,
    conflicting_vendor_signals: false,
    corpus_version: 'edge-corpus-contract-v1',
    evidence_json: {
      vendor_matches: [{
        vendor: 'cloudflare',
        name: 'Cloudflare',
        confidence: 0.94,
        matched_signals: [{ signal: 'server_label', tier: 'high' }],
      }],
      address_matches: [{ family: 'waf', provider: 'cloudflare' }],
      cname_matches: [{ provider: 'cloudfront', type: 'cdn', suffix: '.cloudfront.net' }],
      dns_cname_chain: ['checkout.example.cloudfront.net'],
      dns_resolved_ips: ['203.0.113.10'],
    },
    observed_at: PORTAL_BASELINE_IDS.frozenAt,
    updated_at: PORTAL_BASELINE_IDS.frozenAt,
  }];
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
});

function assertConforms(label, value, shape) {
  const result = validateShape(value, shape);
  assert.equal(
    result.ok,
    true,
    `${label} shape mismatch:\n${result.issues.join('\n')}`,
  );
}

function ownerHeaders(tenantId = PORTAL_BASELINE_IDS.tenantId) {
  return demoHeaders('owner', tenantId, 'usr_owner');
}

async function liveGet(path, tenantId = PORTAL_BASELINE_IDS.tenantId) {
  const res = await request(baseUrl, 'GET', path, { headers: ownerHeaders(tenantId) });
  assert.notEqual(res.status, 404, `GET ${path} must be registered (got 404)`);
  return res;
}

describe('portal response shapes (FT-SHAPE-01..06)', () => {
  it('FT-SHAPE-01 GET /v1/targets/:id conforms to target-detail schema', async () => {
    const live = await liveGet(`/v1/targets/${PORTAL_BASELINE_IDS.targetId}`);
    assert.equal(live.status, 200);
    assertConforms('live target-detail', live.json, TARGET_DETAIL_SHAPE);
    assert.equal(live.json.target?.id, PORTAL_BASELINE_IDS.targetId);
    assert.equal(live.json.target.declaration.purpose_status === 'declared'
      || live.json.target.declaration.purpose_status === 'inherited'
      || live.json.target.declaration.purpose_status === 'unassigned', true);
    assert.equal(live.json.protection_profile.origin.binding_id, null);
    assert.ok(['not_tested', 'unknown'].includes(live.json.protection_profile.origin.status));
    assert.equal(typeof live.json.coverage.unknown_count, 'number');
    assert.equal(typeof live.json.coverage.partial_count, 'number');
    assert.equal(live.json.edge_detection?.test_run_id, PORTAL_BASELINE_IDS.readinessRunId);
    assert.equal(live.json.edge_detection?.waf?.provider, 'cloudflare');
    assert.ok(typeof live.json.counts?.runs_total === 'number');
    assert.ok(live.json.runs_recent.length > 0);
    assert.equal(Object.hasOwn(live.json.runs_recent[0], 'agent_id'), false);
  });

  it('FT-SHAPE-01b target-detail documents and returns the trusted target.tags list (ADR-0008)', async () => {
    // Tags are the membership mechanism (env:<name> replaced environments), so the documented
    // schema must require them as string[] rather than tolerate or drop them.
    assert.deepEqual(TARGET_DETAIL_SHAPE.target.tags, ['string']);
    const target = baselineStore.targets.find((entry) => entry.id === PORTAL_BASELINE_IDS.targetId);
    const previousMetadata = target.metadata;
    target.metadata = { ...(previousMetadata ?? {}), tags: ['env:prod', 'team:edge'] };
    try {
      const live = await liveGet(`/v1/targets/${PORTAL_BASELINE_IDS.targetId}`);
      assert.equal(live.status, 200);
      assertConforms('live tagged target-detail', live.json, TARGET_DETAIL_SHAPE);
      assert.deepEqual(live.json.target.tags, ['env:prod', 'team:edge']);
    } finally {
      target.metadata = previousMetadata;
    }

    const base = (await liveGet(`/v1/targets/${PORTAL_BASELINE_IDS.targetId}`)).json;
    const missing = structuredClone(base);
    delete missing.target.tags;
    const missingResult = validateShape(missing, TARGET_DETAIL_SHAPE);
    assert.equal(missingResult.ok, false);
    assert.ok(missingResult.issues.includes('$.target.tags: missing required field'));

    const malformed = structuredClone(base);
    malformed.target.tags = ['env:prod', 7];
    const malformedResult = validateShape(malformed, TARGET_DETAIL_SHAPE);
    assert.equal(malformedResult.ok, false);
    assert.ok(malformedResult.issues.some((issue) => issue.startsWith('$.target.tags[1]')));
  });

  it('FT-SHAPE-01c history read fields stay explicit arrays on profile and coverage', async () => {
    const live = await liveGet(`/v1/targets/${PORTAL_BASELINE_IDS.targetId}`);
    assert.equal(live.status, 200);
    for (const parent of ['protection_profile', 'coverage']) {
      for (const key of ['retained_family_states', 'comparable_changes', 'origin_bindings']) {
        assert.ok(Array.isArray(live.json[parent][key]), `${parent}.${key}`);
      }
    }

    const accepted = structuredClone(live.json);
    accepted.protection_profile.comparable_changes = [{
      family: 'waf',
      previous_id: 'obs_prev',
      observation_id: 'obs_next',
      comparable: true,
      reason: null,
      change: 'changed',
      direction: 'appeared',
    }];
    assert.equal(validateShape(accepted, TARGET_DETAIL_SHAPE).ok, true);

    const unknown = structuredClone(accepted);
    unknown.protection_profile.retained_family_states = [{
      family: 'waf',
      last_successful: { id: 'obs_1', cookie: 'session' },
      latest_failed_attempt: null,
      fresh_negative: false,
      provider_loss: false,
    }];
    const unknownResult = validateShape(unknown, TARGET_DETAIL_SHAPE);
    assert.equal(unknownResult.ok, false);
    assert.ok(unknownResult.issues.some((issue) => issue.includes('undocumented field') || issue.includes('missing required field')));

    const loose = structuredClone(live.json);
    loose.coverage.origin_bindings = { id: 'obind_1' };
    const looseResult = validateShape(loose, TARGET_DETAIL_SHAPE);
    assert.equal(looseResult.ok, false);
    assert.ok(looseResult.issues.some((issue) => issue.startsWith('$.coverage.origin_bindings')));

    const missing = structuredClone(live.json);
    delete missing.coverage.retained_family_states;
    const missingResult = validateShape(missing, TARGET_DETAIL_SHAPE);
    assert.equal(missingResult.ok, false);
    assert.ok(missingResult.issues.includes('$.coverage.retained_family_states: missing required field'));
  });

  it('FT-SHAPE-02 GET /v1/findings/:id/evidence conforms to evidence schema', async () => {
    const live = await liveGet(`/v1/findings/${PORTAL_BASELINE_IDS.findingId}/evidence`);
    assert.equal(live.status, 200);
    assert.ok(!live.json?.meta?.empty_reason, 'baseline finding must return sealed evidence bundle');
    assertConforms('live evidence', live.json, EVIDENCE_SHAPE);
    assert.ok(live.json.bundle?.id);
    assert.ok(live.json.artifacts?.length > 0);
  });

  it('FT-SHAPE-02b finding detail exposes the strict retest lineage with latest status/finalized/completed_at', async () => {
    const live = await liveGet(`/v1/findings/${PORTAL_BASELINE_IDS.findingId}`);
    assert.equal(live.status, 200);
    assert.ok(live.json.lineage && typeof live.json.lineage === 'object', 'lineage is always present');
    assertConforms('live finding lineage', live.json.lineage, FINDING_LINEAGE_SHAPE);
    // The latest attempt is explicit: an unfinalized run stays pending and can never
    // advance remediation on its own.
    const latest = live.json.lineage.latest;
    if (latest) {
      for (const key of ['test_run_id', 'relation', 'status', 'finalized', 'completed_at', 'pending', 'can_advance_remediation']) {
        assert.ok(Object.hasOwn(latest, key), `latest.${key} must be explicit`);
      }
      assert.equal(latest.finalized, Boolean(latest.completed_at != null || ['completed', 'verdicted'].includes(latest.status)));
      assert.equal(latest.can_advance_remediation, false);
    }
  });

  it('FT-SHAPE-03 GET /v1/waf/coverage/summary conforms to summary schema', async () => {
    const live = await liveGet('/v1/waf/coverage/summary');
    assert.equal(live.status, 200);
    assertConforms('live waf summary', live.json, WAF_SUMMARY_SHAPE);
    assert.equal(typeof live.json.coverage_pct, 'number');
  });

  it('FT-SHAPE-04 verification-ladder conforms to ladder schema', async () => {
    const live = await liveGet(
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/verification-ladder`,
    );
    assert.equal(live.status, 200);
    assertConforms('live verification ladder', live.json, VERIFICATION_LADDER_SHAPE);
    // ADR-0008 removed the agent rung: declared -> dns_verified -> user_confirmed (3 steps).
    assert.ok(Array.isArray(live.json.steps) && live.json.steps.length === 3);
  });

  it('FT-SHAPE-05 list endpoints return { items, count, meta } envelope', async () => {
    const live = await liveGet('/v1/target-groups');
    assert.equal(live.status, 200);
    assert.ok(Array.isArray(live.json?.items), 'list must not be a bare array');
    const envelope = validateListEnvelope(live.json);
    assert.equal(envelope.ok, true, envelope.issues.join('\n'));
    assert.equal(live.json.count, live.json.items.length);
  });

  it('FT-SHAPE-06 empty lists carry meta.empty_reason from live endpoint', async () => {
    seedPortalEmpty();
    const live = await liveGet('/v1/target-groups', PORTAL_EMPTY_IDS.tenantId);
    assert.equal(live.status, 200);
    assert.equal(live.json.count, 0);
    assert.deepEqual(live.json.items, []);
    const envelope = validateListEnvelope(live.json, { requireEmptyReason: true });
    assert.equal(envelope.ok, true, envelope.issues.join('\n'));
    assert.equal(typeof live.json.meta.empty_reason, 'string');
    assert.ok(live.json.meta.empty_reason.trim().length > 0);

    const missingReason = validateListEnvelope({ items: [], count: 0, meta: {} }, { requireEmptyReason: true });
    assert.equal(missingReason.ok, false);
    assert.ok(missingReason.issues.some((issue) => issue.includes('empty_reason')));
  });
});