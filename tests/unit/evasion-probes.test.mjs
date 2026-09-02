import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  WAF_EVASION_PROBE_KIND,
  MAX_WAF_EVASION_MARKER_REQUESTS,
  EVASION_TRANSFORMS,
  EVASION_MARKER_CLASSES,
  applyEvasionTransform,
  buildEvasionMarkerProfile,
  runWafEvasionMarkerProbe,
} from '../../src/lib/vectorProbes/evasionProbes.mjs';
import { BENIGN_CLASS_MARKERS } from '../../src/lib/outsideInWafScanner.mjs';
import { buildProbeProfile } from '../../src/contracts/checks.mjs';
import {
  PROPOSED_PROBE_KINDS,
  PROPOSED_PROFILE_FIELDS,
  PROPOSED_CHECKS,
  PROPOSED_REGISTRY_MAPPING,
  PROPOSED_TIER_RECLASSIFICATION,
  EVASION_COVERAGE_SUMMARY,
} from '../../src/contracts/manifests/evasion.manifest.mjs';

const OWNED_EVA_IDS = 'EVA-004,EVA-005,EVA-006,EVA-007,EVA-008,EVA-009,EVA-010,EVA-011,EVA-012,EVA-013,EVA-015,EVA-017,EVA-018,EVA-019,EVA-020,EVA-022,EVA-023,EVA-024,EVA-025,EVA-026,EVA-027,EVA-028,EVA-029,EVA-030,EVA-031,EVA-032,EVA-033,EVA-034,EVA-035,EVA-036,EVA-037,EVA-038,EVA-041,EVA-044,EVA-045,EVA-046,EVA-047,EVA-048,EVA-049,EVA-050,EVA-051,EVA-058,EVA-059,EVA-060,EVA-061,EVA-062,EVA-063,EVA-065,EVA-066,EVA-067,EVA-068,EVA-069,EVA-070,EVA-071,EVA-072,EVA-073,EVA-077,EVA-079,EVA-080,EVA-081,EVA-083,EVA-084,EVA-085,EVA-086,EVA-087,EVA-088,EVA-089,EVA-090,EVA-091'.split(',');

const FORBIDDEN_SUBSTRINGS = [
  '<script', 'onerror=', 'onload=', 'union select', 'drop table',
  'sleep(', 'benchmark(', 'rm -rf', '/etc/passwd', ' or 1=1', "'or'1'='1", '1=1--',
];

const BENIGN_MARKER_VALUES = new Set(Object.values(BENIGN_CLASS_MARKERS));

function fakeResponse(status, headers = {}) {
  return { status, headers };
}

function countingFetch(statusesByIndex) {
  let index = 0;
  const calls = [];
  const fetchFn = async (url, opts) => {
    calls.push({ url, opts });
    const status = typeof statusesByIndex === 'function'
      ? statusesByIndex(index)
      : (statusesByIndex[index] ?? 403);
    index += 1;
    return fakeResponse(status);
  };
  return { fetchFn, calls: () => calls };
}

test('coverage: registry mapping accounts for exactly the 69 owned EVA IDs', () => {
  const mapped = PROPOSED_REGISTRY_MAPPING.map((m) => m.registry_id);
  assert.equal(new Set(mapped).size, mapped.length, 'no duplicate registry_id');
  assert.deepEqual([...new Set(mapped)].sort(), [...OWNED_EVA_IDS].sort());
  assert.equal(EVASION_COVERAGE_SUMMARY.total, 69);
});

test('coverage: every mapping leaves E0 with a valid tier', () => {
  for (const m of PROPOSED_REGISTRY_MAPPING) {
    assert.ok(['E1', 'E3', 'E4'].includes(m.target_tier), `${m.registry_id} tier`);
    assert.ok(Array.isArray(m.add_check_ids) && m.add_check_ids.length > 0, `${m.registry_id} has a check`);
  }
});

test('probe kind: single bounded kind, <=8 requests', () => {
  assert.equal(PROPOSED_PROBE_KINDS.length, 1);
  assert.equal(PROPOSED_PROBE_KINDS[0].kind, WAF_EVASION_PROBE_KIND);
  assert.equal(PROPOSED_PROBE_KINDS[0].max_requests, MAX_WAF_EVASION_MARKER_REQUESTS);
  assert.ok(MAX_WAF_EVASION_MARKER_REQUESTS <= 8);
  assert.equal(PROPOSED_PROFILE_FIELDS.length, 2);
});

test('generated profiles preserve the catalog default while explicit budgets reduce or clamp', () => {
  const generated = buildEvasionMarkerProfile({ transform: 'double_url', marker_class: 'sqli' });
  const reduced = buildEvasionMarkerProfile({ transform: 'double_url', max_requests: 1 });
  const clamped = buildEvasionMarkerProfile({ transform: 'double_url', max_requests: 99, rate: 50 });
  assert.equal(generated.max_requests, 4);
  assert.equal(reduced.max_requests, 1);
  assert.equal(clamped.max_requests, MAX_WAF_EVASION_MARKER_REQUESTS);
});

test('every evasion transform wraps an inert marker and emits nothing exploitable', () => {
  for (const transform of EVASION_TRANSFORMS) {
    for (const cls of EVASION_MARKER_CLASSES) {
      const variant = applyEvasionTransform(transform, cls);
      assert.ok(BENIGN_MARKER_VALUES.has(variant.marker), `${transform}/${cls} uses a benign base marker`);
      assert.ok(variant.sent_value.length <= 512, `${transform} bounded length`);
      const lowered = variant.sent_value.toLowerCase();
      for (const bad of FORBIDDEN_SUBSTRINGS) {
        assert.ok(!lowered.includes(bad), `${transform}/${cls} must not contain ${bad}`);
      }
    }
  }
});

test('manifest evasion profiles are bounded and carry contract-valid metadata', () => {
  const evasionChecks = PROPOSED_CHECKS.filter((c) => c.probe_profile.kind === WAF_EVASION_PROBE_KIND);
  assert.equal(evasionChecks.length, 41);
  for (const check of evasionChecks) {
    const p = check.probe_profile;
    assert.ok(p.max_requests <= MAX_WAF_EVASION_MARKER_REQUESTS, `${check.check_id} <=8`);
    assert.ok(p.timeout_ms <= 5000, `${check.check_id} timeout`);
    assert.equal(p.expected_action, 'block');
    assert.equal(p.scenario_family, 'marker');
    // The metadata subset our profiles carry must survive the real contract validator.
    const validated = buildProbeProfile({
      kind: 'waf_enforcement_probe',
      marker: p.marker,
      marker_type: p.marker_type,
      scenario_family: p.scenario_family,
      expected_action: p.expected_action,
      nonce_hash_only: p.nonce_hash_only,
      collect: p.collect,
    });
    assert.equal(validated.scenario_family, 'marker');
    assert.equal(validated.expected_action, 'block');
    assert.equal(validated.nonce_hash_only, true);
    assert.ok(validated.collect.includes('evasion_bypass_suspected'));
  }
});

test('inspection-limit check validates through the real buildProbeProfile', () => {
  const check = PROPOSED_CHECKS.find((c) => c.check_id === 'waf.inspection_limit.safe');
  assert.ok(check);
  const validated = buildProbeProfile(check.probe_profile);
  assert.equal(validated.kind, 'waf_inspection_limit_probe');
  assert.ok(validated.max_requests <= 6);
  assert.equal(validated.http_method, 'POST');
  assert.equal(validated.nonce_hash_only, true);
});

test('runner: requires signed worker / injectable deps (fails closed)', async () => {
  const job = { target: { value: 'https://example.test' }, probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }) };
  const res = await runWafEvasionMarkerProbe(job, {});
  assert.equal(res.external_result, 'error');
  assert.equal(res.metadata.error_class, 'live_probe_requires_signed_worker');
  assert.equal(res.requests_sent, 0);
});

test('runner: evasion resisted when transformed marker still blocked', async () => {
  const { fetchFn, calls } = countingFetch([403, 403]);
  const job = { target: { value: 'https://example.test' }, probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }) };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn });
  assert.equal(res.external_result, 'external_blocked');
  assert.equal(res.metadata.evasion_bypass_suspected, false);
  assert.ok(calls().length <= MAX_WAF_EVASION_MARKER_REQUESTS);
});

test('runner: evasion suspected when transformed marker passes but baseline blocked', async () => {
  const { fetchFn } = countingFetch([403, 200]);
  const job = { target: { value: 'https://example.test' }, probe_profile: buildEvasionMarkerProfile({ transform: 'html_entity', marker_class: 'xss' }) };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn });
  assert.equal(res.external_result, 'external_allowed');
  assert.equal(res.metadata.evasion_bypass_suspected, true);
});

test('runner: inconclusive when baseline not blocked', async () => {
  const { fetchFn } = countingFetch([200, 200]);
  const job = { target: { value: 'https://example.test' }, probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }) };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn });
  assert.equal(res.external_result, 'inconclusive');
});

test('runner: request budget is hard-bounded and retains no response body', async () => {
  const { fetchFn, calls } = countingFetch(() => 403);
  const job = {
    target: { value: 'https://example.test' },
    probe_profile: { ...buildEvasionMarkerProfile({ transform: 'double_url' }), max_requests: 999 },
  };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn });
  assert.ok(res.requests_sent <= MAX_WAF_EVASION_MARKER_REQUESTS);
  assert.ok(calls().length <= MAX_WAF_EVASION_MARKER_REQUESTS);
  for (const entry of res.metadata.variant_results) {
    assert.deepEqual(Object.keys(entry).sort(), ['blocked', 'label', 'sent_length', 'status_code']);
  }
});

test('runner: preserves the signed target path/query and honors a worker cap of one', async () => {
  const { fetchFn, calls } = countingFetch([403, 403]);
  const job = {
    target: { value: 'https://example.test/signed/path?keep=1' },
    constraints: { max_requests: 99, max_probe_requests: 1 },
    probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }),
  };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn });
  assert.equal(res.requests_sent, 1);
  assert.equal(res.external_result, 'inconclusive');
  assert.equal(calls().length, 1);
  const sent = new URL(calls()[0].url);
  assert.equal(sent.pathname, '/signed/path');
  assert.equal(sent.searchParams.get('keep'), '1');
  assert.ok(sent.searchParams.has('probe'));
});

test('runner: stops after the first transport failure', async () => {
  let calls = 0;
  const job = {
    target: { value: 'https://example.test/signed/path' },
    probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }),
  };
  const res = await runWafEvasionMarkerProbe(job, {
    fetchFn: async () => {
      calls += 1;
      throw Object.assign(new Error('temporary failure'), { code: 'ECONNRESET' });
    },
  });
  assert.equal(calls, 1);
  assert.equal(res.requests_sent, 1);
  assert.equal(res.external_result, 'inconclusive');
});

test('runner: honours job deadline (stops before sending)', async () => {
  const { fetchFn, calls } = countingFetch(() => 403);
  const job = {
    target: { value: 'https://example.test' },
    deadline_at: 1000,
    probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }),
  };
  const res = await runWafEvasionMarkerProbe(job, { fetchFn, now: () => 2000 });
  assert.equal(res.requests_sent, 0);
  assert.equal(calls().length, 0);
});

test('tier reclassification: E4 governed families are recognized, E1 posture justified', () => {
  const allowedFamilies = new Set(['residential_proxy', 'rate_limit_evasion', 'adaptive_evasion']);
  for (const r of PROPOSED_TIER_RECLASSIFICATION) {
    assert.ok(typeof r.reason === 'string' && r.reason.length > 10, `${r.registry_id} reason`);
    if (r.target_tier === 'E4') {
      assert.ok(allowedFamilies.has(r.governed_scenario_family), `${r.registry_id} family`);
    }
  }
});
