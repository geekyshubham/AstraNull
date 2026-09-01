import test from 'node:test';
import assert from 'node:assert/strict';

import {
  WAF_CLASS_MARKER_PROBE_KIND,
  WAF_CLASS_PROBE_MAX_REQUESTS,
  WAF_CLASS_MARKERS,
  WAF_MARKER_CLASSES,
  WAF_E3_MARKER_CLASSES,
  BENIGN_MARKER_SENTINEL,
  FORBIDDEN_PAYLOAD_SIGNATURES,
  isInertMarker,
  buildWafClassProbeProfile,
  runWafClassMarkerProbe,
} from '../../src/lib/vectorProbes/wafClassProbes.mjs';

import {
  PROPOSED_PROBE_KINDS,
  PROPOSED_PROFILE_FIELDS,
  PROPOSED_CHECKS,
  PROPOSED_REGISTRY_MAPPING,
  PROPOSED_TIER_RECLASSIFICATION,
  PROPOSED_CATALOG_COVERAGE,
} from '../../src/contracts/manifests/waf-class.manifest.mjs';

import {
  buildProbeProfile,
  ALLOWED_PROBE_PROFILE_KINDS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
  isCustomerRunnable,
} from '../../src/contracts/checks.mjs';

import { validateCheckVectorSafetyPolicy } from '../../scripts/vector-safety-policy-evidence.mjs';

const OWNED_IDS = 'WAF-002,WAF-003,WAF-004,WAF-005,WAF-006,WAF-007,WAF-008,WAF-009,WAF-010,WAF-011,WAF-013,WAF-014,WAF-015,WAF-016,WAF-017,WAF-020,WAF-022,WAF-024,WAF-033,WAF-034,WAF-035,WAF-036,WAF-038,WAF-039,WAF-047,WAF-048,WAF-049,WAF-050,WAF-051,WAF-052,WAF-053,WAF-054,WAF-055,WAF-056,WAF-057,WAF-058,WAF-059,WAF-060,WAF-061,WAF-062,WAF-063,WAF-064,WAF-065,WAF-066,WAF-067,WAF-068,WAF-080,WAF-081,WAF-084,WAF-086,WAF-087,WAF-088,WAF-089,WAF-090,WAF-091,WAF-092,WAF-093,WAF-095,WAF-099,WAF-101,WAF-104,WAF-105,WAF-106,WAF-107,WAF-108,WAF-109,WAF-110,WAF-111,WAF-113,WAF-114,WAF-115,WAF-116,WAF-117,WAF-118,WAF-119,WAF-120,WAF-121,WAF-122,WAF-124,WAF-125,WAF-126,WAF-128,WAF-130,WAF-132,WAF-134,WAF-136,WAF-138,WAF-139,WAF-140,WAF-141,WAF-142,WAF-143,WAF-144,WAF-145,WAF-146,WAF-147,WAF-151,WAF-153,WAF-154,WAF-155,WAF-157,WAF-158,WAF-161,WAF-163,WAF-164,WAF-165,WAF-166,WAF-167,WAF-168,WAF-169,WAF-170,WAF-171,WAF-172,WAF-173,WAF-174,WAF-175,WAF-176'.split(',');

function okResponse(status, headers = {}) {
  return { status, headers: new Map(Object.entries(headers)) };
}

test('every marker is inert: embeds the benign sentinel and no working-payload signature', () => {
  for (const marker of Object.values(WAF_CLASS_MARKERS)) {
    assert.ok(String(marker).toLowerCase().includes(BENIGN_MARKER_SENTINEL), `missing sentinel: ${marker}`);
    assert.ok(isInertMarker(marker), `marker not classified inert: ${marker}`);
    for (const sig of FORBIDDEN_PAYLOAD_SIGNATURES) {
      assert.ok(!String(marker).toLowerCase().includes(sig.toLowerCase()), `payload signature ${sig} in ${marker}`);
    }
  }
});

test('URL-bearing markers only target the RFC-6761 .invalid sink, never live/metadata hosts', () => {
  for (const key of ['ssrf', 'xxe', 'open_redirect', 'ldap', 'cors_marker']) {
    const marker = WAF_CLASS_MARKERS[key];
    assert.ok(marker.includes('.invalid'), `${key} marker must use .invalid: ${marker}`);
    assert.ok(!marker.includes('169.254'), `${key} marker must not reference link-local metadata`);
  }
});

test('isInertMarker rejects a working payload', () => {
  assert.equal(isInertMarker('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(isInertMarker('astranull; system(id)'), false);
  assert.equal(isInertMarker('no-sentinel-here'), false);
});

test('probe kind is bounded at 8 with no rate/count/repeat parameter exposed', () => {
  assert.equal(WAF_CLASS_PROBE_MAX_REQUESTS, 8);
  const profile = buildWafClassProbeProfile({ marker_class: 'ssrf' });
  assert.equal(profile.kind, WAF_CLASS_MARKER_PROBE_KIND);
  assert.equal(profile.max_requests, 8);
  for (const forbidden of ['rate', 'max_rate', 'count', 'repeat', 'concurrency', 'rps', 'qps']) {
    assert.ok(!(forbidden in profile), `profile must not expose ${forbidden}`);
  }
});

test('buildWafClassProbeProfile clamps oversized requests to the ceiling', () => {
  const profile = buildWafClassProbeProfile({ marker_class: 'nosql', max_requests: 9999, timeout_ms: 999999 });
  assert.equal(profile.max_requests, WAF_CLASS_PROBE_MAX_REQUESTS);
  assert.ok(profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS);
});

test('buildWafClassProbeProfile rejects an unknown marker class', () => {
  assert.throws(() => buildWafClassProbeProfile({ marker_class: 'not_a_class' }));
});

test('a blocking WAF is graded protected', async () => {
  let calls = 0;
  const fetchFn = async (url, init) => {
    calls += 1;
    const carriesMarker = String(url).includes('astranull') || Boolean(init?.headers?.['x-astranull-marker']);
    return okResponse(carriesMarker ? 403 : 200);
  };
  const result = await runWafClassMarkerProbe({ url: 'https://target.example/api', marker_class: 'ssrf', fetchFn });
  assert.equal(result.posture, 'protected');
  assert.ok(result.requests_sent <= WAF_CLASS_PROBE_MAX_REQUESTS);
  assert.ok(calls <= WAF_CLASS_PROBE_MAX_REQUESTS);
  assert.equal(result.marker_inert, true);
});

test('a permissive WAF is graded exposed', async () => {
  const fetchFn = async () => okResponse(200);
  const result = await runWafClassMarkerProbe({ url: 'https://target.example/api', marker_class: 'xxe', fetchFn });
  assert.equal(result.posture, 'exposed');
  assert.ok(result.allowed_count >= 1);
});

test('probe honours the request bound across all placements', async () => {
  let calls = 0;
  const fetchFn = async () => { calls += 1; return okResponse(200); };
  const result = await runWafClassMarkerProbe({ url: 'https://target.example/', marker_class: 'crlf', fetchFn });
  assert.ok(calls <= WAF_CLASS_PROBE_MAX_REQUESTS, `sent ${calls} requests`);
  assert.equal(result.requests_sent, calls);
});

test('probe refuses to run without an injected transport (no real network)', async () => {
  const result = await runWafClassMarkerProbe({ url: 'https://target.example/', marker_class: 'ssrf' });
  assert.equal(result.error_class, 'no_transport');
  assert.equal(result.requests_sent, 0);
});

test('proposed probe kind is registered and accepted by buildProbeProfile (integration wired it in)', () => {
  assert.ok(ALLOWED_PROBE_PROFILE_KINDS.includes(WAF_CLASS_MARKER_PROBE_KIND));
  assert.equal(
    buildProbeProfile({ kind: WAF_CLASS_MARKER_PROBE_KIND, max_requests: 8 }).kind,
    WAF_CLASS_MARKER_PROBE_KIND,
  );
  assert.equal(PROPOSED_PROBE_KINDS[0].kind, WAF_CLASS_MARKER_PROBE_KIND);
  assert.equal(PROPOSED_PROBE_KINDS[0].max_requests, 8);
  assert.equal(PROPOSED_PROFILE_FIELDS[0].field, 'marker_class');
});

test('every proposed E3 check is safety-policy compliant apart from the not-yet-registered kind', () => {
  assert.equal(PROPOSED_CHECKS.length, WAF_E3_MARKER_CLASSES.length);
  for (const check of PROPOSED_CHECKS) {
    assert.equal(check.safety_class, 'safe');
    assert.ok(isCustomerRunnable(check), `${check.check_id} must be customer runnable`);
    assert.equal(check.probe_profile.kind, WAF_CLASS_MARKER_PROBE_KIND);
    assert.ok(check.probe_profile.max_requests <= WAF_CLASS_PROBE_MAX_REQUESTS);
    assert.ok(check.probe_profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS);
    assert.ok(isInertMarker(check.probe_profile.marker), `${check.check_id} marker must be inert`);

    const result = validateCheckVectorSafetyPolicy(check);
    assert.deepEqual(result.missing_fields, [], `${check.check_id} missing: ${JSON.stringify(result.missing_fields)}`);
    assert.deepEqual(result.forbidden_fields, [], `${check.check_id} forbidden: ${JSON.stringify(result.forbidden_fields)}`);
    // Integration has registered the probe kind, so the check now validates fully green.
    assert.deepEqual(result.invalid_fields, [], `${check.check_id} unexpected invalid: ${JSON.stringify(result.invalid_fields)}`);
  }
});

test('E3 registry mapping references only defined E3 checks', () => {
  const checkIds = new Set(PROPOSED_CHECKS.map((c) => c.check_id));
  for (const mapping of PROPOSED_REGISTRY_MAPPING) {
    assert.equal(mapping.target_tier, 'E3');
    for (const id of mapping.add_check_ids) {
      assert.ok(checkIds.has(id), `mapping references unknown check ${id}`);
    }
  }
  // Every defined check is actually attached to a registry entry.
  const mapped = new Set(PROPOSED_REGISTRY_MAPPING.flatMap((m) => m.add_check_ids));
  for (const id of checkIds) assert.ok(mapped.has(id), `check ${id} not mapped to any registry entry`);
});

test('E4/E1 reclassifications carry a concrete reason', () => {
  for (const entry of PROPOSED_TIER_RECLASSIFICATION) {
    assert.ok(['E4', 'E1'].includes(entry.target_tier));
    assert.ok(entry.reason && entry.reason.length > 20, `${entry.registry_id} needs a reason`);
    if (entry.target_tier === 'E1') assert.ok(entry.posture_fact, `${entry.registry_id} needs posture_fact`);
    if (entry.target_tier === 'E4') assert.ok(entry.governed_requirement, `${entry.registry_id} needs governed_requirement`);
  }
});

test('all 117 owned catalog vectors leave E0 exactly once', () => {
  const covered = [];
  const e3Registries = new Set(PROPOSED_REGISTRY_MAPPING.map((m) => m.registry_id));
  const reclassRegistries = new Set(PROPOSED_TIER_RECLASSIFICATION.map((r) => r.registry_id));

  for (const row of PROPOSED_CATALOG_COVERAGE) {
    assert.ok(['E3', 'E4', 'E1'].includes(row.tier));
    if (row.tier === 'E3') {
      assert.ok(e3Registries.has(row.registry_id), `${row.registry_id} E3 without a registry mapping`);
    } else {
      assert.ok(reclassRegistries.has(row.registry_id), `${row.registry_id} ${row.tier} without a reclassification`);
    }
    covered.push(...row.catalog_vector_ids);
  }

  assert.equal(covered.length, OWNED_IDS.length, 'coverage count mismatch');
  assert.equal(new Set(covered).size, OWNED_IDS.length, 'duplicate catalog id in coverage');
  assert.deepEqual([...covered].sort(), [...OWNED_IDS].sort(), 'coverage set must equal the owned bucket');

  // No owned id may remain E0.
  const byTier = { E3: 0, E4: 0, E1: 0 };
  for (const row of PROPOSED_CATALOG_COVERAGE) byTier[row.tier] += row.catalog_vector_ids.length;
  assert.equal(byTier.E3 + byTier.E4 + byTier.E1, 117);
});

test('marker classes cover the E3 families and the enum lists every family', () => {
  for (const cls of WAF_E3_MARKER_CLASSES) {
    assert.ok(WAF_MARKER_CLASSES.includes(cls), `enum missing ${cls}`);
    assert.ok(typeof WAF_CLASS_MARKERS[cls] === 'string', `no marker for ${cls}`);
  }
});
