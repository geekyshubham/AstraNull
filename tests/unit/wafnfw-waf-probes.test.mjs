import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  WAF_CHALLENGED_OUTCOME,
  WAF_GRADING_VERSION,
  WAF_RESPONSE_OUTCOMES,
  SIGNATURE_CORPUS_VERSION,
  VENDOR_DENIAL_SIGNATURES,
  matchDeclaredDenialSignature,
  matchVendorDenialSignature,
} from '../../src/lib/externalObservationOutcomes.mjs';
import {
  isBlockedOrChallenged,
  markerBaselineHealth,
  markerResponseSnapshot,
} from '../../src/lib/outsideInWafScanner.mjs';
import { deriveAttemptObservation } from '../../src/lib/entryPathComparison.mjs';
import {
  applyEvasionTransform,
  OBSERVATION_ONLY_TRANSFORMS,
  runWafEvasionMarkerProbe,
  buildEvasionMarkerProfile,
} from '../../src/lib/vectorProbes/evasionProbes.mjs';
import {
  assuranceScopeForMarkerClass,
  runWafClassMarkerProbe,
  WAF_CLASS_MARKERS,
} from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { CACHE_BUSTER_PARAM } from '../../src/lib/vectorProbes/wafProbeSupport.mjs';
import { BENIGN_CLASS_MARKERS } from '../../src/lib/inertWafMarkers.mjs';

function headers(map = {}) {
  const lower = Object.fromEntries(Object.entries(map).map(([k, v]) => [String(k).toLowerCase(), v]));
  return {
    get: (name) => lower[String(name).toLowerCase()] ?? null,
    forEach: (fn) => Object.entries(lower).forEach(([name, value]) => fn(value, name)),
  };
}

function res(status, hdrs = {}, body = '') {
  return { status, headers: headers(hdrs), bodyText: body, body_complete: true };
}

const BLOCK = { 'x-waf-block': '1' };
const CHALLENGE = { 'cf-mitigated': 'challenge', 'cf-ray': '8a1-LHR', server: 'cloudflare' };

function markerish(url, init) {
  return String(url).includes('astranull') || Boolean(init?.headers?.['x-astranull-marker']) || String(url).includes('probe=');
}

describe('T1 WAF marker probes and grading', () => {
  it('1 ban cascade: a ban on the first marker makes the result source_penalized, not protected', async () => {
    let n = 0;
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/',
      marker_class: 'ssrf',
      fetchFn: async () => {
        n += 1;
        return n === 1
          ? res(200)
          : res(403, { server: 'cloudflare', 'cf-ray': '1' }, 'Error code: 1006 Access denied Cloudflare');
      },
      rng: () => 0.99,
    });
    assert.equal(result.source_penalized, true);
    assert.equal(result.posture_status, 'source_penalized');
    assert.equal(result.enforcement, 'unknown');
    assert.equal(result.posture, 'inconclusive');
    assert.notEqual(result.posture, 'protected');
    assert.equal(result.trailing_control.outcome, 'blocked');
    assert.ok(result.leg_order.length >= 1);
    assert.equal(result.cache_buster, true);
  });

  it('1 injected RNG randomizes marker leg order and records it', async () => {
    const fetchFn = async () => res(200);
    const identity = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'sqli', fetchFn, rng: () => 0.99,
    });
    const rotated = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'ssrf', fetchFn, rng: () => 0,
    });
    assert.deepEqual(identity.leg_order, ['query', 'path', 'header']);
    assert.notDeepEqual(rotated.leg_order, identity.leg_order);
    assert.deepEqual([...rotated.leg_order].sort(), ['header', 'path', 'query']);
  });

  it('2 every request carries a cache-buster nonce query param and records cache_status', async () => {
    const urls = [];
    const fetchFn = async (url) => {
      urls.push(String(url));
      return res(200, { 'cf-cache-status': 'DYNAMIC' });
    };
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'sqli', fetchFn, rng: () => 0.99, nonce: 'run-nonce-1',
    });
    assert.ok(urls.length >= 5);
    for (const url of urls) {
      assert.ok(new URL(url).searchParams.get(CACHE_BUSTER_PARAM), url);
    }
    assert.equal(new Set(urls.map((url) => new URL(url).searchParams.get(CACHE_BUSTER_PARAM))).size, urls.length);
    assert.ok(result.placements.every((row) => row.cache_status === 'DYNAMIC'));
  });

  it('3 a 404 path leg is excluded and does not void query or header', async () => {
    const fetchFn = async (url, init) => {
      if (!markerish(url, init)) return res(200);
      if (new URL(url).pathname.includes('astranull')) return res(404);
      return res(403, BLOCK);
    };
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'sqli', fetchFn, rng: () => 0.99,
    });
    const byPlacement = Object.fromEntries(result.placements.map((row) => [row.placement, row]));
    assert.equal(byPlacement.path.outcome, 'inconclusive');
    assert.equal(byPlacement.query.outcome, 'blocked');
    assert.equal(byPlacement.header.outcome, 'blocked');
    assert.equal(result.enforcement, 'enforced');
    assert.equal(result.posture, 'protected');
    assert.ok(result.planned_marker_legs >= 1);
    assert.equal(result.planned_marker_legs, result.completed_marker_legs);
  });

  it('4 a challenge never yields enforced', async () => {
    const fetchFn = async (url, init) => (markerish(url, init) ? res(403, CHALLENGE) : res(200));
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'sqli', fetchFn, rng: () => 0.99,
    });
    assert.ok(result.placements.every((row) => row.outcome === 'challenged'));
    assert.equal(result.enforcement, 'challenged');
    assert.notEqual(result.enforcement, 'enforced');
    assert.equal(result.posture, 'inconclusive');
    assert.ok(WAF_RESPONSE_OUTCOMES.includes(WAF_CHALLENGED_OUTCOME));
  });

  it('4 F16: a signed denial on the permitted baseline is inconclusive, not consistent enforcement', () => {
    const derived = deriveAttemptObservation({
      external_result: 'blocked',
      probe_metadata: {
        profile_kind: 'waf_class_marker_probe',
        permitted_baseline: { status_code: 403, denial_signature: { kind: 'vendor', id: 'cloudflare_challenge', vendor: 'cloudflare' } },
        comparison_complete: true,
        planned_marker_legs: 3,
        completed_marker_legs: 3,
        marker_results: [{ blocked: true, allowed: false }],
      },
    });
    assert.equal(derived.observation, null);
    assert.ok(derived.reasons.includes('permitted_baseline_signed_denial'));
    assert.equal(derived.enforcement, 'unknown');
  });

  it('5 a 3xx whose Location differs from the baseline grades redirected, never allowed', () => {
    const baseline = markerResponseSnapshot(res(200, { location: '/home' }));
    const marker = markerResponseSnapshot(res(302, { location: '/cdn-cgi/block' }));
    const graded = isBlockedOrChallenged(marker, baseline);
    assert.equal(graded.outcome, 'redirected');
    assert.equal(graded.redirected, true);
    assert.equal(graded.allowed, false);
    assert.equal(graded.location_changed, true);
    const same = isBlockedOrChallenged(markerResponseSnapshot(res(302, { location: '/home' })), baseline);
    assert.equal(same.outcome, 'allowed');
    assert.equal(same.reason, 'not_blocked_at_the_edge');
  });

  it('6 new vendor signatures are live_verified false and grade blocked only on a WAF-specific anchor', () => {
    const needed = [
      'aws_alb_waf_block', 'aws_apigateway_waf_block', 'gcp_cloud_armor_block',
      'azure_frontdoor_waf_block', 'fastly_ngwaf_block', 'modsecurity_default_block',
    ];
    for (const id of needed) {
      const rule = VENDOR_DENIAL_SIGNATURES.find((row) => row.id === id);
      assert.ok(rule, id);
      assert.equal(rule.live_verified, false, id);
      assert.equal(typeof rule.suspect, 'function', id);
    }
    const alb = matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { server: 'awselb/2.0' }),
      bodyText: '<html>Request blocked by AWS WAF</html>',
    });
    assert.equal(alb.id, 'aws_alb_waf_block');
    assert.equal(matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { server: 'awselb/2.0' }),
      bodyText: '<html>403 Forbidden</html>',
    }), null);
    assert.equal(matchVendorDenialSignature({
      statusCode: 200,
      headers: res(200, { server: 'awselb/2.0' }),
      bodyText: '<html>Request blocked by AWS WAF</html>',
    }), null);
    assert.equal(matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { 'x-amzn-errortype': 'ForbiddenException' }),
      bodyText: 'Forbidden',
    }), null);
    const armor = matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { via: '1.1 google' }),
      bodyText: 'Cloud Armor Forbidden',
    });
    assert.equal(armor.id, 'gcp_cloud_armor_block');
    const azure = matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { 'x-azure-ref': '0abc' }),
      bodyText: 'Azure Front Door: the request is blocked by WAF policy',
    });
    assert.equal(azure.id, 'azure_frontdoor_waf_block');
    assert.equal(matchVendorDenialSignature({
      statusCode: 406,
      headers: res(406, { 'x-served-by': 'cache-lhr' }),
      bodyText: '',
    }), null);
    const modsec = matchVendorDenialSignature({
      statusCode: 403,
      headers: res(403, { server: 'Apache/2.4 (mod_security)' }),
      bodyText: 'This error was generated by mod_security',
    });
    assert.equal(modsec.id, 'modsecurity_default_block');
  });

  it('6 declared signature matches end to end; matching the baseline is inconclusive', async () => {
    const declared = { header_name: 'x-block-ref', header_value: 'edge-policy', status_codes: [406] };
    assert.ok(matchDeclaredDenialSignature({
      statusCode: 406, headers: res(406, { 'x-block-ref': 'edge-policy' }), declared,
    }));
    assert.ok(matchDeclaredDenialSignature({
      statusCode: 406,
      headers: res(406, { 'x-block-ref': 'edge-policy' }),
      declared: { status_code: 406, header: { name: 'x-block-ref', value: 'edge-policy' } },
    }));
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/',
      marker_class: 'ssrf',
      declared_block_signature: { header_name: 'x-block-ref', header_value: 'edge-policy' },
      fetchFn: async () => res(200, { 'x-block-ref': 'edge-policy' }),
    });
    assert.equal(result.posture, 'inconclusive');
    assert.equal(result.inconclusive_reason, 'custom_canary_rule_setup_unavailable');
    assert.equal(result.enforcement, 'unknown');
  });

  it('7 a Protected by trust seal on a 200 page does not mark the baseline unhealthy', () => {
    const snapshot = markerResponseSnapshot(
      res(200, { server: 'nginx' }, 'Welcome. Protected by Wordfence. Protected by FortiGate.'),
    );
    assert.equal(snapshot.block_page_signature_id, null);
    assert.equal(markerBaselineHealth(snapshot), 'healthy');
  });

  it('8 fullwidth mapping is the correct code point for every ASCII character and changes the SQL text', () => {
    const variant = applyEvasionTransform('unicode_normalization', 'sqli');
    assert.notEqual(variant.sent_value, BENIGN_CLASS_MARKERS.sqli);
    const mapped = [...BENIGN_CLASS_MARKERS.sqli].map((c) => {
      const code = c.codePointAt(0);
      if (code === 0x20) return '\u3000';
      if (code >= 0x21 && code <= 0x7e) return String.fromCodePoint(code + 0xfee0);
      return c;
    }).join('');
    assert.equal(variant.sent_value, mapped);
    assert.equal(variant.sent_value.includes('astranull'), false);
  });

  it('8 observation-only transforms never produce a normalization_gap', async () => {
    for (const transform of OBSERVATION_ONLY_TRANSFORMS) {
      assert.equal(applyEvasionTransform(transform, 'sqli').observation_only, true, transform);
      let n = 0;
      const fetchFn = async () => {
        n += 1;
        if (n === 1 || n === 4) return res(200);
        return n === 3 ? res(200) : res(403, BLOCK);
      };
      const result = await runWafEvasionMarkerProbe({
        target: { value: 'https://example.test' },
        probe_profile: buildEvasionMarkerProfile({ transform }),
      }, { fetchFn, rng: () => 0.99 });
      assert.equal(result.metadata.reference_outcome, 'blocked', transform);
      assert.equal(result.metadata.transform_outcome, 'allowed', transform);
      assert.equal(result.metadata.normalization_gap, false, transform);
      assert.equal(result.metadata.observation_only, true, transform);
      assert.notEqual(result.external_result, 'external_allowed', transform);
    }
  });

  it('8 evasion emits reference_outcome, transform_outcome, and a trailing control', async () => {
    const fetchFn = async (url) => (markerish(url) ? res(403, BLOCK) : res(200));
    const result = await runWafEvasionMarkerProbe({
      target: { value: 'https://example.test' },
      probe_profile: { ...buildEvasionMarkerProfile({ transform: 'double_url' }), transform: 'double_url' },
    }, { fetchFn, rng: () => 0.99 });
    assert.equal(result.metadata.reference_outcome, 'blocked');
    assert.equal(result.metadata.transform_outcome, 'blocked');
    assert.equal(result.metadata.normalization_gap, false);
    assert.equal(result.metadata.reference_not_enforced, false);
    assert.equal(result.metadata.trailing_control.outcome, 'allowed');
    assert.equal(result.metadata.source_penalized, false);
    assert.equal(result.external_result, 'external_blocked');
    const padding = applyEvasionTransform('benign_padding', 'sqli');
    assert.ok(padding.sent_value.length >= 2048);
    assert.ok(Buffer.byteLength(padding.sent_value) <= 8192);
    for (const transform of ['double_url', 'mixed_url', 'case_fold']) {
      const applied = applyEvasionTransform(transform, 'sqli');
      assert.notEqual(applied.sent_value, BENIGN_CLASS_MARKERS.sqli, transform);
    }
  });

  it('8 a ban after the first evasion leg is source_penalized, not a resisted transform', async () => {
    let n = 0;
    const fetchFn = async () => {
      n += 1;
      return n === 1 ? res(200) : res(403, BLOCK);
    };
    const result = await runWafEvasionMarkerProbe({
      target: { value: 'https://example.test' },
      probe_profile: buildEvasionMarkerProfile({ transform: 'double_url' }),
    }, { fetchFn, rng: () => 0.99 });
    assert.equal(result.metadata.source_penalized, true);
    assert.equal(result.external_result, 'inconclusive');
    assert.equal(result.metadata.normalization_gap, false);
    assert.notEqual(result.external_result, 'external_blocked');
  });

  it('9 plain sqli/xss/path_traversal markers are managed_rule_marker; ssti is an opaque custom_canary_rule token', async () => {
    for (const markerClass of ['sqli', 'xss', 'path_traversal']) {
      assert.equal(assuranceScopeForMarkerClass(markerClass), 'managed_rule_marker');
      assert.ok(String(WAF_CLASS_MARKERS[markerClass]).toLowerCase().includes('astranull'));
      const result = await runWafClassMarkerProbe({
        url: 'https://target.example/', marker_class: markerClass, fetchFn: async () => res(200), rng: () => 0.99,
      });
      assert.equal(result.assurance_scope, 'managed_rule_marker');
    }
    assert.equal(assuranceScopeForMarkerClass('ssti'), 'custom_canary_rule');
    assert.ok(String(WAF_CLASS_MARKERS.ssti).toLowerCase().includes('astranull'));
    const ssti = await runWafClassMarkerProbe({
      url: 'https://target.example/', marker_class: 'ssti', fetchFn: async () => res(200), rng: () => 0.99,
    });
    assert.equal(ssti.assurance_scope, 'custom_canary_rule');
    assert.equal(assuranceScopeForMarkerClass('ssrf'), 'custom_canary_rule');
  });

  it('9 entry-path probes send GET only so a body signature can be seen', async () => {
    const methods = [];
    const fetchFn = async (url, init) => {
      methods.push(init.method);
      return markerish(url, init)
        ? res(200, {}, '<html>The requested URL was rejected. Please consult with your administrator. Your support ID is: 99</html>')
        : res(200, {}, '<html>ok</html>');
    };
    const result = await runWafClassMarkerProbe({
      url: 'https://app.example/login',
      marker_class: 'sqli',
      entry_path_scenario: 'declared_login_path',
      fetchFn,
      rng: () => 0.99,
    });
    assert.ok(methods.every((method) => method === 'GET'));
    assert.ok(result.marker_results.some((row) => row.blocked && row.denial_signature?.vendor === 'f5'));
  });

  it('10 class-marker results emit enforcement, assurance_scope, grading versions, and redacted features', async () => {
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/',
      marker_class: 'ssrf',
      fetchFn: async (url, init) => (markerish(url, init)
        ? res(403, { ...BLOCK, 'set-cookie': 'sid=secret', authorization: 'Bearer x' })
        : res(200)),
      rng: () => 0.99,
    });
    assert.equal(result.enforcement, 'unknown');
    assert.equal(result.produces_verdict, false);
    assert.equal(result.setup_required, true);
    assert.equal(result.assurance_scope, 'custom_canary_rule');
    assert.equal(result.grading_version, WAF_GRADING_VERSION);
    assert.equal(result.signature_corpus_version, SIGNATURE_CORPUS_VERSION);
    assert.ok(Array.isArray(result.response_features));
    assert.ok(result.response_features.length > 0);
    const blob = JSON.stringify(result.response_features);
    assert.equal(blob.includes('sid=secret'), false);
    assert.equal(blob.includes('Bearer'), false);
    assert.equal(blob.includes('set-cookie'), false);
  });

  it('11 class markers run / plus declared same-host paths and skip extras that exceed the budget', async () => {
    const seen = [];
    const fetchFn = async (url) => {
      seen.push(new URL(url).pathname);
      return res(200);
    };
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/app',
      marker_class: 'ssrf',
      max_requests: 8,
      declarations: { waf: { marker_paths: ['/login', '/api', '/admin', '/extra', '/six', 'https://other.example/x'] } },
      fetchFn,
      rng: () => 0.99,
    });
    assert.equal(result.paths[0]?.path, '/app');
    assert.ok(result.paths.some((row) => row.path === '/'));
    assert.ok(result.paths_skipped >= 1);
    assert.ok(result.requests_sent <= 8);
    assert.equal(seen.some((path) => path.includes('other.example')), false);
  });
});
