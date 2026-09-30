import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import {
  EVIDENCE_SHAPE,
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

before(() => {
  process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
  const store = seedPortalBaseline();
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
    assert.equal(live.json.edge_detection?.test_run_id, PORTAL_BASELINE_IDS.readinessRunId);
    assert.equal(live.json.edge_detection?.waf?.provider, 'cloudflare');
    assert.ok(typeof live.json.counts?.runs_total === 'number');
    assert.ok(live.json.runs_recent.length > 0);
    assert.equal(Object.hasOwn(live.json.runs_recent[0], 'agent_id'), false);
  });

  it('FT-SHAPE-02 GET /v1/findings/:id/evidence conforms to evidence schema', async () => {
    const live = await liveGet(`/v1/findings/${PORTAL_BASELINE_IDS.findingId}/evidence`);
    assert.equal(live.status, 200);
    assert.ok(!live.json?.meta?.empty_reason, 'baseline finding must return sealed evidence bundle');
    assertConforms('live evidence', live.json, EVIDENCE_SHAPE);
    assert.ok(live.json.bundle?.id);
    assert.ok(live.json.artifacts?.length > 0);
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