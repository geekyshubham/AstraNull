import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CHECK_CATALOG,
  buildProbeProfile,
  checkRequiresAdditionalInput,
  customerSelectableChecks,
  getCheckById,
  isCustomerRunnable,
} from '../../src/contracts/checks.mjs';
import { normalizeEntryPathDeclaration } from '../../src/contracts/protectionValidation.mjs';
import { targetKindCompatibilityError } from '../../src/contracts/checkTargetCompatibility.mjs';
import { probeWafClassMarker } from '../../src/lib/capabilityProbes.mjs';
import { approvedScenarioVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { deriveAttemptObservation, selectEntryPathCheck } from '../../src/lib/entryPathComparison.mjs';
import { evidenceTierForCheck } from '../../src/lib/probeEvidenceTiers.mjs';
import {
  ENTRY_PATH_SAFE_METHODS,
  WAF_CLASS_MARKERS,
  WAF_CLASS_PROBE_MAX_REQUESTS,
  buildEntryPathRequest,
  entryPathVariations,
  isInertMarker,
  runWafClassMarkerProbe,
} from '../../src/lib/vectorProbes/wafClassProbes.mjs';

const TENANT = 'ten_demo';
const LOGIN_ID = 'waf.entry_path_login_marker.safe';
const API_ID = 'waf.entry_path_api_marker.safe';
const ENTRY_CHECKS = Object.freeze([
  { id: LOGIN_ID, scenario: 'declared_login_path', relation: 'declared_login_url', setup: 'declared_login_entry_path', url: 'https://app.example/login' },
  { id: API_ID, scenario: 'declared_api_path', relation: 'declared_api_url', setup: 'declared_api_entry_path', url: 'https://api.example:8443/v1/orders' },
]);
const CREDENTIAL_FIELD = /pass(word)?|passwd|user(name)?|email|login=|otp|token|session|cookie|authorization|csrf/i;

function relationFor(kind, targetId) {
  return {
    id: `ep_${kind}`,
    ...normalizeEntryPathDeclaration({
      owner: 'App Team',
      purpose: 'Declared route',
      expected_behavior: 'must_be_protected_by_layers',
      required_layers: ['waf'],
      entry_target_id: targetId,
      relation_kind: kind,
    }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }),
  };
}

function urlTarget(id, value) {
  return { id, tenant_id: TENANT, target_group_id: 'tg_1', kind: 'url', value };
}

function response(status) {
  return { status, headers: new Map(status === 403 ? [['cf-mitigated', 'challenge']] : []) };
}

function isMarkerRequest(url, init) {
  return String(url).includes('astranull_') || Boolean(init?.headers?.['x-astranull-marker']);
}

function recordingFetch(decide) {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url: String(url), init });
    return response(decide(String(url), init));
  };
  return { calls, fetchFn };
}

function variantOf(url, init) {
  if (init?.headers?.['x-astranull-padding']) return 'header_marker_after_padding';
  if (init?.headers?.['x-astranull-marker']) return 'header_marker';
  if (url.includes('astranull_pad=')) return 'query_marker_after_padding';
  if (init?.headers?.['content-type']) return 'query_marker_content_type';
  if (url.includes('%25')) return 'query_marker_double_encoded';
  if (url.includes('%61%73')) return 'query_marker_percent_encoded';
  if (url.includes('astranull_')) return 'query_marker';
  return 'baseline';
}

describe('declared login/API entry-path catalog checks', () => {
  it('ships bounded, url-only, customer-runnable WAF checks that set entry_path_scenario', () => {
    const neighbour = getCheckById('waf.http_method_policy_marker.safe');
    for (const spec of ENTRY_CHECKS) {
      const check = getCheckById(spec.id);
      assert.ok(check, spec.id);
      assert.equal(check.version, '1.0.0');
      assert.equal(check.vector_family, 'waf');
      assert.equal(check.safety_class, 'safe');
      assert.equal(check.risk_class, 'safe');
      assert.deepEqual(check.supported_targets, ['url']);
      assert.equal(check.default_expected_behavior, 'must_block_before_origin');
      assert.ok(check.required_customer_setup.includes(spec.setup));
      assert.ok(check.required_customer_setup.includes('customer_approves_waf_marker_probe'));
      assert.deepEqual(check.safety_constraints, neighbour.safety_constraints);
      assert.deepEqual(check.stop_conditions, neighbour.stop_conditions);
      assert.equal(check.probe_profile.kind, 'waf_class_marker_probe');
      assert.equal(check.probe_profile.entry_path_scenario, spec.scenario);
      assert.ok(check.probe_profile.max_requests <= WAF_CLASS_PROBE_MAX_REQUESTS);
      assert.ok(check.probe_profile.timeout_ms <= 5000);
      assert.equal(check.probe_profile.marker, WAF_CLASS_MARKERS[check.probe_profile.marker_class]);
      assert.ok(isInertMarker(check.probe_profile.marker));
      assert.equal(approvedScenarioVersion(check), 'marker');
      assert.equal(isCustomerRunnable(check), true);
      assert.equal(checkRequiresAdditionalInput(check), false);
      assert.equal(evidenceTierForCheck(check), 'E3');
      assert.ok(check.attack_vector_ids.includes('ATT-247'));
    }
    assert.equal(CHECK_CATALOG.filter((check) => check.probe_profile?.entry_path_scenario).length, 2);
    const selectable = new Set(customerSelectableChecks(CHECK_CATALOG).map((check) => check.check_id));
    assert.ok(selectable.has(LOGIN_ID) && selectable.has(API_ID));
  });

  it('keeps entry_path_scenario through the signed probe-profile builder', () => {
    for (const spec of ENTRY_CHECKS) {
      const rebuilt = buildProbeProfile(getCheckById(spec.id).probe_profile);
      assert.equal(rebuilt.entry_path_scenario, spec.scenario);
      assert.equal(rebuilt.max_requests, 8);
      assert.equal(rebuilt.permitted_baseline, undefined);
    }
  });

  it('rejects fqdn and ip targets for the url-only checks', () => {
    for (const spec of ENTRY_CHECKS) {
      const check = getCheckById(spec.id);
      assert.equal(targetKindCompatibilityError(check, { kind: 'url', value: spec.url }), null);
      assert.equal(targetKindCompatibilityError(check, { kind: 'fqdn', value: 'app.example' }).error, 'target_kind_not_supported');
      assert.equal(targetKindCompatibilityError(check, { kind: 'ip', value: '203.0.113.10' }).error, 'target_kind_not_supported');
    }
  });
});

describe('entry-path planner preference', () => {
  it('prefers the declared login/API check for marker-family and generic marker scenarios', () => {
    for (const spec of ENTRY_CHECKS) {
      const target = urlTarget(`tgt_${spec.relation}`, spec.url);
      const relation = relationFor(spec.relation, target.id);
      for (const scenario of ['marker', 'waf.marker_rule.safe', spec.id]) {
        const selected = selectEntryPathCheck({ relation, entryTarget: target, scenario, catalog: CHECK_CATALOG });
        assert.equal(selected.check?.check_id, spec.id, `${spec.relation} ${scenario}`);
      }
    }
  });

  it('keeps class-specific scenarios and non-entry relations on their own checks', () => {
    const login = urlTarget('tgt_login', 'https://app.example/login');
    const ssrf = selectEntryPathCheck({ relation: relationFor('declared_login_url', login.id), entryTarget: login, scenario: 'waf.ssrf_marker.safe', catalog: CHECK_CATALOG });
    assert.equal(ssrf.check.check_id, 'waf.ssrf_marker.safe');
    const alt = urlTarget('tgt_alt', 'https://alt.example/');
    const alternate = selectEntryPathCheck({ relation: relationFor('alternate_hostname', alt.id), entryTarget: alt, scenario: 'waf.marker_rule.safe', catalog: CHECK_CATALOG });
    assert.equal(alternate.check.check_id, 'waf.marker_rule.safe');
    const blocked = selectEntryPathCheck({ relation: relationFor('declared_login_url', login.id), entryTarget: login, scenario: 'waf.inspection_limit.safe', catalog: CHECK_CATALOG });
    assert.equal(blocked.reason, 'login_path_state_change_risk');
  });

  it('falls back to the scenario check when the declared path is not a url target', () => {
    const fqdn = { id: 'tgt_api_host', tenant_id: TENANT, target_group_id: 'tg_1', kind: 'fqdn', value: 'api.example' };
    const selected = selectEntryPathCheck({ relation: relationFor('declared_api_url', fqdn.id), entryTarget: fqdn, scenario: 'waf.marker_rule.safe', catalog: CHECK_CATALOG });
    assert.equal(selected.check.check_id, 'waf.marker_rule.safe');
  });
});

describe('entry-path probe safety and the blocked-baseline prerequisite', () => {
  it('sends only GET/HEAD, no body, no credential fields, no redirects, and never changes host or path', async () => {
    for (const spec of ENTRY_CHECKS) {
      const check = getCheckById(spec.id);
      const { calls, fetchFn } = recordingFetch((url, init) => (isMarkerRequest(url, init) ? 403 : 200));
      const result = await runWafClassMarkerProbe({ url: spec.url, ...check.probe_profile, fetchFn });
      const signed = new URL(spec.url);
      assert.ok(calls.length <= check.probe_profile.max_requests);
      assert.equal(result.requests_sent, calls.length);
      for (const call of calls) {
        assert.ok(ENTRY_PATH_SAFE_METHODS.includes(call.init.method));
        assert.equal(call.init.body, undefined);
        assert.equal(call.init.redirect, 'manual');
        const sent = new URL(call.url);
        assert.equal(sent.host, signed.host);
        assert.equal(sent.pathname, signed.pathname);
        for (const name of sent.searchParams.keys()) assert.equal(CREDENTIAL_FIELD.test(name), false, name);
        for (const name of Object.keys(call.init.headers)) assert.equal(CREDENTIAL_FIELD.test(name), false, name);
      }
      assert.equal(result.entry_path_scenario, spec.scenario);
      assert.equal(result.posture, 'protected');
      assert.equal(result.gated_variation_count, 0);
    }
  });

  it('puts different bytes on the wire for each encoding variant', () => {
    const plain = buildEntryPathRequest('https://app.example/login', 'sqli', entryPathVariations('declared_login_path')[0]).url;
    const percent = buildEntryPathRequest('https://app.example/login', 'sqli', entryPathVariations('declared_login_path')[1]).url;
    const double = buildEntryPathRequest('https://api.example/v1', 'sqli', entryPathVariations('declared_api_path')[1]).url;
    assert.notEqual(plain, percent);
    assert.ok(percent.includes('%61%73%74%72%61%6E%75%6C%6C'));
    assert.ok(double.includes('%2520'));
    assert.equal(new URL(percent).searchParams.get('astranull_sqli_probe'), WAF_CLASS_MARKERS.sqli);
  });

  it('names a plain reference for every evasion and inspection-limit variant', () => {
    for (const scenario of ['declared_login_path', 'declared_api_path']) {
      const plan = entryPathVariations(scenario);
      const names = plan.map((row) => row.variation);
      for (const row of plan) {
        const dependent = row.encoding !== 'plain' || row.content_type || row.padding_bytes;
        if (!dependent) {
          assert.equal(row.reference, undefined, row.variation);
          continue;
        }
        assert.ok(names.indexOf(row.reference) >= 0 && names.indexOf(row.reference) < names.indexOf(row.variation), row.variation);
      }
    }
  });

  it('grades a variant that slips past a blocked plain marker as exposed', async () => {
    const check = getCheckById(API_ID);
    const { fetchFn } = recordingFetch((url, init) => {
      const variant = variantOf(url, init);
      if (variant === 'baseline') return 200;
      return variant === 'query_marker_after_padding' ? 200 : 403;
    });
    const result = await runWafClassMarkerProbe({ url: 'https://api.example/v1', ...check.probe_profile, fetchFn });
    const padded = result.marker_results.find((row) => row.phase === 'query_marker_after_padding');
    assert.equal(padded.blocked_baseline_prerequisite, 'met');
    assert.equal(padded.allowed, true);
    assert.equal(result.enforcement, 'partial');
    assert.equal(result.posture, 'exposed');
  });

  it('keeps variants inconclusive when the plain marker was allowed and ignores them in enforcement', async () => {
    const check = getCheckById(LOGIN_ID);
    const { fetchFn } = recordingFetch((url, init) => {
      const variant = variantOf(url, init);
      return variant === 'baseline' || variant === 'query_marker' ? 200 : 403;
    });
    const result = await runWafClassMarkerProbe({ url: 'https://app.example/login', ...check.probe_profile, fetchFn });
    for (const phase of ['query_marker_percent_encoded', 'query_marker_form_content_type', 'query_marker_after_padding']) {
      const row = result.marker_results.find((entry) => entry.phase === phase);
      assert.equal(row.blocked_baseline_prerequisite, 'not_met', phase);
      assert.equal(row.inconclusive, true);
      assert.equal(row.blocked, false);
      assert.equal(row.allowed, false);
    }
    assert.equal(result.marker_results.find((row) => row.phase === 'header_marker_after_padding').blocked_baseline_prerequisite, 'met');
    assert.equal(result.gated_variation_count, 3);
    assert.equal(result.enforcement, 'partial');
    const observed = deriveAttemptObservation({ external_result: 'connected', probe_metadata: { profile_kind: 'waf_class_marker_probe', ...result } });
    assert.equal(observed.enforcement, 'partial');
  });

  it('never turns unresolved evidence into protection', async () => {
    const check = getCheckById(LOGIN_ID);
    const { fetchFn } = recordingFetch((url, init) => {
      const variant = variantOf(url, init);
      if (init.method === 'HEAD') return 403;
      return variant === 'baseline' || variant === 'query_marker' ? 200 : 403;
    });
    const result = await runWafClassMarkerProbe({ url: 'https://app.example/login', ...check.probe_profile, fetchFn });
    const headerPadding = result.marker_results.find((row) => row.phase === 'header_marker_after_padding');
    assert.equal(headerPadding.blocked_baseline_prerequisite, 'not_observed');
    assert.equal(headerPadding.inconclusive, true);
    assert.equal(result.blocked_count, 0);
    assert.equal(result.enforcement, 'not_enforced');
    assert.notEqual(result.posture, 'protected');
  });

  it('dispatches the catalog profile through the signed executor with the entry-path scenario and nonce', async () => {
    const check = getCheckById(LOGIN_ID);
    let captured = null;
    const outcome = await probeWafClassMarker({
      constraints: { max_requests: 8, timeout_ms: 1000 },
      probe_profile: check.probe_profile,
      target: { kind: 'url', value: 'https://app.example/login' },
      nonce: 'nonce-abc',
    }, {
      signedJobVerified: true,
      fetchFn: async () => response(200),
      wafClassProbeFn: async (options) => {
        captured = options;
        return { posture: 'inconclusive', marker_results: [], phases: [] };
      },
    });
    assert.equal(captured.entry_path_scenario, 'declared_login_path');
    assert.equal(captured.expected_nonce, 'nonce-abc');
    assert.equal(captured.marker_class, 'sqli');
    assert.ok(captured.max_requests <= 8);
    assert.equal(outcome.external_result, 'not_run');
  });
});
