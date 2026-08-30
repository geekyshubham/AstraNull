import './dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { sha256Hex } from '../../src/lib/authorizationArtifactLedger.mjs';
import { computeTargetGroupScopeHash } from '../../src/lib/scopeHash.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from './http.mjs';

/** Pre–SOC-009 expansion artifact set (for negative authorization-pack tests). */
export const LEGACY_REQUIRED_ARTIFACT_TYPES = [
  'customer_authorization_letter',
  'target_ownership_confirmation',
  'emergency_contacts',
  'stop_criteria',
  'test_plan',
];

function defaultProofWindow() {
  return {
    valid_from: new Date().toISOString(),
    valid_to: new Date(Date.now() + 86400000 * 30).toISOString(),
  };
}

export function artifactProofBody(type, overrides = {}) {
  const base = {
    type,
    content_sha256: sha256Hex(`artifact-proof:${type}`),
    reference_uri: 'metadata://pack/demo',
    approval_reference: 'REF-DEMO-001',
    approver: 'Customer Approver',
    valid_window: defaultProofWindow(),
    approved_targets: ['tg_1'],
    approved_scenario_families: ['udp_flood'],
    max_rate: '1000_rps_metadata',
    max_duration_minutes: 30,
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    retention_policy: { retain_days: 90, classification: 'governance' },
  };
  return { ...base, ...overrides };
}


function artifactProofForRequest(type, request, overrides = {}) {
  const scopeHash = computeTargetGroupScopeHash(request.tenant_id, request.target_group_id);
  return artifactProofBody(type, {
    valid_window: {
      valid_from: request.requested_window.window_start,
      valid_to: request.requested_window.window_end,
    },
    approved_targets: [request.target_group_id],
    approved_scenario_families: [...request.requested_scenario_families],
    approved_delivery_patterns: [...request.delivery_patterns],
    approved_limits: { ...request.requested_limits },
    authorization_binding: {
      tenant_id: request.tenant_id,
      target_group_id: request.target_group_id,
      scope_hash: scopeHash,
      requested_window: { ...request.requested_window },
      approved_schedule_window: { ...request.requested_window },
      delivery_patterns: [...request.delivery_patterns],
    },
    ...overrides,
  });
}
export function validHighScaleRequestPayload(overrides = {}) {
  const windowStart = new Date(Date.now() - 60_000).toISOString();
  const windowEnd = new Date(Date.now() + 172800000).toISOString();
  return {
    target_group_id: 'tg_1',
    objective: 'Scheduled readiness drill',
    environment: 'staging',
    business_criticality: 'high',
    requested_scenario_families: ['udp_flood'], delivery_patterns: ['direct'],
    requested_limits: { max_gbps: 0.5, max_duration_minutes: 45 },
    stop_criteria: { abort_on_customer_signal: true, max_error_rate_pct: 5 },
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    requested_window: {
      window_start: windowStart,
      window_end: windowEnd,
      timezone: 'UTC',
    },
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    provider_context: { provider_name: 'Cloudflare' },
    scope_confirmation: true,
    ...overrides,
  };
}

export async function acceptRequiredAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders) {
  const req = getStore().highScaleRequests.find((row) => row.id === hsId);
  assert.ok(req, `missing high-scale request ${hsId}`);
  for (const type of REQUIRED_ARTIFACT_TYPES) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: artifactProofForRequest(type, req),
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}

export async function acceptLegacyAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders) {
  const req = getStore().highScaleRequests.find((row) => row.id === hsId);
  assert.ok(req, `missing high-scale request ${hsId}`);
  for (const type of LEGACY_REQUIRED_ARTIFACT_TYPES) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: artifactProofForRequest(type, req),
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}

export async function acceptHighScaleAuthorizationPack(baseUrl, hsId, socHeaders) {
  await acceptRequiredAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders);
  const req = getStore().highScaleRequests.find((r) => r.id === hsId);
  for (const item of req?.provider_approval_checklist ?? []) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: {
        ...artifactProofForRequest('provider_approval', req),
        type: 'provider_approval',
        provider_name: item.provider_name,
        reference_uri: 'metadata://pack/provider',
        approval_reference: 'PROV-REF-001',
        contact_path: 'provider-war-room@example.invalid',
        provider_specific_evidence: {
          approval_path: item.approval_path ?? 'manual_coordination',
          provider_key: item.provider_key ?? 'generic',
        },
        emergency_stop_path: 'provider-stop-bridge',
      },
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}
