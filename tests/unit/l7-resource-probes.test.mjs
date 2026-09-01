import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  probeL7ResourcePosture,
  buildL7ResourcePostureProfile,
  boundedPostureTimeoutMs,
  L7_RESOURCE_POSTURE_PROBE_KIND,
  L7_RESOURCE_POSTURE_MAX_REQUESTS,
  L7_POSTURE_MARKER_CLASSES,
  INERT_POSTURE_MARKER_BODY,
  MAX_ACTUAL_REQUEST_BYTES,
} from '../../src/lib/vectorProbes/l7ResourceProbes.mjs';
import {
  MANIFEST_ID,
  OWNED_REGISTRY_IDS,
  PROPOSED_PROBE_KINDS,
  PROPOSED_PROFILE_FIELDS,
  PROPOSED_CHECKS,
  PROPOSED_REGISTRY_MAPPING,
  PROPOSED_TIER_RECLASSIFICATION,
} from '../../src/contracts/manifests/l7-resource.manifest.mjs';
import {
  CHECK_CATALOG,
  buildProbeProfile,
  ALLOWED_PROBE_PROFILE_KINDS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
} from '../../src/contracts/checks.mjs';
import { GOVERNED_SCENARIO_FAMILIES } from '../../src/contracts/governedScenarios.mjs';
import { EXHAUSTED_RESOURCE_FAMILIES } from '../../src/contracts/resourceExhaustionTaxonomy.mjs';
import { evidenceTierForProbeKind } from '../../src/lib/probeEvidenceTiers.mjs';

const OWNED_68 = [
  'APP-004', 'APP-012', 'APP-023', 'APP-025', 'APP-026', 'APP-028', 'APP-029', 'APP-032',
  'APP-033', 'APP-034', 'APP-035', 'APP-036', 'APP-037', 'APP-038', 'APP-039', 'APP-041',
  'APP-044', 'APP-045', 'APP-046', 'APP-047', 'APP-049', 'APP-057', 'APP-060', 'APP-067',
  'APP-071', 'APP-075', 'APP-076', 'APP-080', 'APP-081', 'APP-082', 'APP-083', 'APP-084',
  'APP-085', 'APP-090', 'APP-091', 'APP-117', 'APP-118', 'APP-119', 'APP-120', 'APP-124',
  'APP-125', 'APP-127', 'APP-129', 'APP-132', 'APP-134', 'APP-135', 'APP-137', 'APP-140',
  'APP-143', 'APP-145', 'APP-146', 'APP-147', 'APP-148', 'APP-152', 'APP-185', 'APP-186',
  'APP-187', 'APP-188', 'APP-189', 'APP-190', 'APP-191', 'APP-194', 'APP-196', 'APP-197',
  'APP-198', 'APP-199', 'APP-200', 'APP-201',
];

const CATALOG_CHECK_IDS = new Set(CHECK_CATALOG.map((c) => c.check_id));
const GOVERNED_FAMILY_IDS = new Set(GOVERNED_SCENARIO_FAMILIES.map((f) => f.id));
const RESOURCE_FAMILY_IDS = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));

function authorizedJob(overrides = {}) {
  return {
    target: { url: 'https://protected.example' },
    probe_profile: { kind: L7_RESOURCE_POSTURE_PROBE_KIND, marker_class: 'declared_content_encoding', timeout_ms: 5000 },
    ...overrides,
  };
}

test('manifest owns exactly the 68 ticketed IDs, no gaps or dupes', () => {
  assert.equal(MANIFEST_ID, 'l7-resource');
  assert.equal(OWNED_REGISTRY_IDS.length, 68);
  assert.deepEqual([...OWNED_REGISTRY_IDS].sort(), [...OWNED_68].sort());
  assert.equal(new Set(OWNED_REGISTRY_IDS).size, 68);
});

test('every owned ID leaves E0 via exactly one mapping or reclassification', () => {
  const covered = new Map();
  const record = (id, tier) => {
    assert.ok(!covered.has(id), `duplicate coverage for ${id}`);
    covered.set(id, tier);
  };
  for (const m of PROPOSED_REGISTRY_MAPPING) record(m.registry_id, m.target_tier);
  for (const r of PROPOSED_TIER_RECLASSIFICATION) record(r.registry_id, r.target_tier);
  assert.equal(covered.size, 68);
  for (const id of OWNED_68) {
    assert.ok(covered.has(id), `missing coverage for ${id}`);
    assert.notEqual(covered.get(id), 'E0');
  }
});

test('registry mappings reference existing or newly-proposed checks and reach their tier', () => {
  const proposedIds = new Set(PROPOSED_CHECKS.map((c) => c.check_id));
  for (const m of PROPOSED_REGISTRY_MAPPING) {
    assert.ok(Array.isArray(m.add_check_ids) && m.add_check_ids.length > 0, `${m.registry_id} has no check`);
    for (const id of m.add_check_ids) {
      assert.ok(CATALOG_CHECK_IDS.has(id) || proposedIds.has(id), `unknown check ${id} for ${m.registry_id}`);
    }
  }
});

test('HTTP/2 frame evidence is E3 while HTTP/3 Alt-Svc observation remains E2', () => {
  const byId = new Map(CHECK_CATALOG.map((c) => [c.check_id, c]));
  const h2 = byId.get('l7.http2_continuation.readiness');
  const h3 = byId.get('protocol.http3_control_stream.readiness');
  assert.equal(h2.probe_profile.kind, 'http2_frame_probe');
  assert.equal(h3.probe_profile.kind, 'http3_control_probe');
  assert.equal(evidenceTierForProbeKind('http2_frame_probe'), 'E3');
  assert.equal(evidenceTierForProbeKind('http3_control_probe'), 'E2');
  assert.equal(
    PROPOSED_REGISTRY_MAPPING.find((row) => row.registry_id === 'APP-196').target_tier,
    'E2',
  );
  const h2Profile = buildProbeProfile({
    kind: 'http2_frame_probe',
    max_requests: 4,
    timeout_ms: 5000,
  });
  const h3Profile = buildProbeProfile({
    kind: 'http3_control_probe',
    max_requests: 1,
    timeout_ms: 5000,
  });
  assert.equal(h2Profile.kind, 'http2_frame_probe');
  assert.equal(h3Profile.kind, 'http3_control_probe');
  assert.ok(h2Profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS);
  assert.ok(h3Profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS);
});

test('E1 cost vectors reuse the existing ops.autoscaling_cost.readiness posture', () => {
  const e1 = PROPOSED_REGISTRY_MAPPING.filter((m) => m.target_tier === 'E1');
  assert.equal(e1.length, 2);
  for (const m of e1) {
    assert.deepEqual(m.add_check_ids, ['ops.autoscaling_cost.readiness']);
    assert.ok(CATALOG_CHECK_IDS.has('ops.autoscaling_cost.readiness'));
  }
});

test('new posture checks are safe, bounded, and use the new probe kind', () => {
  assert.equal(PROPOSED_CHECKS.length, 2);
  for (const check of PROPOSED_CHECKS) {
    assert.equal(check.safety_class, 'safe');
    assert.equal(check.probe_profile.kind, L7_RESOURCE_POSTURE_PROBE_KIND);
    assert.ok(check.probe_profile.max_requests <= L7_RESOURCE_POSTURE_MAX_REQUESTS);
    assert.ok(check.probe_profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS);
    assert.ok(L7_POSTURE_MARKER_CLASSES.includes(check.probe_profile.marker_class));
    assert.ok(CATALOG_CHECK_IDS.has(check.check_id), 'integration registered the new check in the catalog');
  }
});

test('the new probe kind is declared and registered in the allowed set (integration added it)', () => {
  assert.deepEqual(PROPOSED_PROBE_KINDS.map((k) => k.kind), [L7_RESOURCE_POSTURE_PROBE_KIND]);
  assert.equal(PROPOSED_PROBE_KINDS[0].max_requests, L7_RESOURCE_POSTURE_MAX_REQUESTS);
  assert.ok(ALLOWED_PROBE_PROFILE_KINDS.includes(L7_RESOURCE_POSTURE_PROBE_KIND));
  assert.equal(
    buildProbeProfile({ kind: L7_RESOURCE_POSTURE_PROBE_KIND, max_requests: 2, marker_class: 'declared_oversize_uri' }).kind,
    L7_RESOURCE_POSTURE_PROBE_KIND,
  );
  // Only marker_class is proposed as a new profile field, scoped to the new kind.
  assert.equal(PROPOSED_PROFILE_FIELDS.length, 1);
  assert.equal(PROPOSED_PROFILE_FIELDS[0].field, 'marker_class');
  assert.deepEqual(PROPOSED_PROFILE_FIELDS[0].applies_to_kinds, [L7_RESOURCE_POSTURE_PROBE_KIND]);
});

test('E4 reclassifications carry a valid resource family, valid-or-null governed family, and a reason', () => {
  const e4 = PROPOSED_TIER_RECLASSIFICATION;
  assert.ok(e4.length >= 1);
  for (const r of e4) {
    assert.equal(r.target_tier, 'E4');
    assert.ok(RESOURCE_FAMILY_IDS.has(r.exhausted_resource), `bad resource ${r.exhausted_resource} for ${r.registry_id}`);
    if (r.governed_scenario_family !== null) {
      assert.ok(GOVERNED_FAMILY_IDS.has(r.governed_scenario_family), `bad governed family ${r.governed_scenario_family} for ${r.registry_id}`);
    }
    assert.ok(typeof r.reason === 'string' && r.reason.length > 20, `weak reason for ${r.registry_id}`);
  }
});

test('buildL7ResourcePostureProfile is hard-bounded and validated', () => {
  const p = buildL7ResourcePostureProfile({ marker_class: 'declared_content_encoding', max_requests: 99, timeout_ms: 999999 });
  assert.equal(p.max_requests, L7_RESOURCE_POSTURE_MAX_REQUESTS);
  assert.equal(p.timeout_ms, MAX_PROBE_PROFILE_TIMEOUT_MS);
  assert.throws(() => buildL7ResourcePostureProfile({ marker_class: 'nope' }), /invalid l7 posture marker_class/);
  assert.equal(boundedPostureTimeoutMs(-5), 5000);
  assert.equal(boundedPostureTimeoutMs(1234), 1234);
});

test('probe grades an enforcing origin as blocked and never exceeds the request bound', () => {
  const sent = [];
  const requestFn = async (url, options) => {
    sent.push({ url, options });
    return { status: 413 };
  };
  return probeL7ResourcePosture(authorizedJob({ signedJobVerified: undefined }), { signedJobVerified: true, requestFn })
    .then((res) => {
      assert.equal(res.external_result, 'blocked');
      assert.ok(res.requests_sent >= 1 && res.requests_sent <= L7_RESOURCE_POSTURE_MAX_REQUESTS);
      assert.equal(res.metadata.body_retained, false);
      assert.equal(res.metadata.declared_only, true);
      // Enforcement short-circuits, so at most the declared bound of requests is sent.
      assert.ok(sent.length <= L7_RESOURCE_POSTURE_MAX_REQUESTS);
    });
});

test('probe grades an accepting origin as connected (exposed posture)', async () => {
  const requestFn = async () => ({ status: 200 });
  const res = await probeL7ResourcePosture(authorizedJob(), { signedJobVerified: true, requestFn });
  assert.equal(res.external_result, 'connected');
});

test('probe fails closed when unauthorized', async () => {
  const requestFn = async () => ({ status: 200 });
  const res = await probeL7ResourcePosture(authorizedJob(), { requestFn });
  assert.equal(res.external_result, 'error');
  assert.equal(res.metadata.error_class, 'probe_not_authorized');
  assert.equal(res.requests_sent, 0);
});

test('probe rejects an unsupported marker class and unroutable target', async () => {
  const requestFn = async () => ({ status: 200 });
  const bad = await probeL7ResourcePosture(
    authorizedJob({ probe_profile: { kind: L7_RESOURCE_POSTURE_PROBE_KIND, marker_class: 'x' } }),
    { signedJobVerified: true, requestFn },
  );
  assert.equal(bad.metadata.error_class, 'unsupported_marker_class');
  const noTarget = await probeL7ResourcePosture(
    authorizedJob({ target: {} }),
    { signedJobVerified: true, requestFn },
  );
  assert.equal(noTarget.metadata.error_class, 'unsupported_target');
});

test('SAFETY: no request the probe can send is a bomb or flood payload', async () => {
  // Inert marker is tiny; the module caps actual bytes far below any bomb.
  assert.ok(Buffer.byteLength(INERT_POSTURE_MARKER_BODY) <= 64);
  assert.ok(MAX_ACTUAL_REQUEST_BYTES <= 4096);

  // Capture every request the probe emits for both marker classes and assert bounded, inert bytes.
  for (const marker_class of L7_POSTURE_MARKER_CLASSES) {
    const emitted = [];
    const requestFn = async (url, options) => {
      emitted.push({ url, options });
      return { status: 200 };
    };
    await probeL7ResourcePosture(
      authorizedJob({ probe_profile: { kind: L7_RESOURCE_POSTURE_PROBE_KIND, marker_class } }),
      { signedJobVerified: true, requestFn },
    );
    assert.ok(emitted.length <= L7_RESOURCE_POSTURE_MAX_REQUESTS);
    for (const { url, options } of emitted) {
      const bodyBytes = typeof options.body === 'string' ? Buffer.byteLength(options.body) : 0;
      const urlBytes = Buffer.byteLength(url);
      assert.ok(bodyBytes <= MAX_ACTUAL_REQUEST_BYTES, `oversize body ${bodyBytes}`);
      assert.ok(urlBytes <= 8192, `oversize url ${urlBytes}`);
      // Declared sizes live in headers only; the body carries no repeated bomb content.
      assert.ok(bodyBytes <= 64);
    }
  }
});

test('SAFETY: probe/manifest sources contain no bomb, flood, or collision generator', () => {
  const probeSrc = readFileSync(fileURLToPath(new URL('../../src/lib/vectorProbes/l7ResourceProbes.mjs', import.meta.url)), 'utf8');
  const manifestSrc = readFileSync(fileURLToPath(new URL('../../src/contracts/manifests/l7-resource.manifest.mjs', import.meta.url)), 'utf8');
  // No compression / archive libraries are pulled in — the probe cannot build a decompression bomb.
  assert.ok(!/from ['"]node:zlib['"]/.test(probeSrc));
  assert.ok(!/require\(['"]zlib['"]\)/.test(probeSrc));
  // No unbounded allocation or large buffer construction.
  assert.ok(!/Buffer\.alloc(?:Unsafe)?\s*\(\s*\d{5,}/.test(probeSrc));
  // The only .repeat in the module is the bounded 1KB URI marker (< MAX_ACTUAL_REQUEST_BYTES).
  const repeats = [...probeSrc.matchAll(/\.repeat\(/g)];
  assert.ok(repeats.length <= 1, 'unexpected repeat() usage');
  // Manifest proposes only marker_class as a new field — no count/rate/concurrency/repeat knob.
  assert.ok(manifestSrc.length > 0);
  for (const f of PROPOSED_PROFILE_FIELDS) {
    assert.equal(f.field, 'marker_class');
  }
});
