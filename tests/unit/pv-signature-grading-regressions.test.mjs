// Regressions for the final PV review: signature-only marker grading, API safe methods, signed baselines, and body signatures.
import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { classifyPathValidationItem } from '../../src/contracts/protectionValidation.mjs';
import { probeWafEnforcement } from '../../src/lib/capabilityProbes.mjs';
import { deriveAttemptObservation, selectEntryPathCheck } from '../../src/lib/entryPathComparison.mjs';
import { runEntryPathMarkerProbe, runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';

const F5_BLOCK_PAGE = '<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br>Your support ID is: 1234567890</body></html>';
const CLOUDFLARE_CHALLENGE = { 'cf-mitigated': 'challenge', 'cf-ray': '8a1b2c3d4e-LHR', server: 'cloudflare' };

function stubResponse(status, headers = {}, body = '') {
  return { status, headers: new Map(Object.entries(headers)), text: async () => body };
}

function carriesMarker(url, init) {
  return String(url).includes('astranull') || Boolean(init?.headers?.['x-astranull-marker']);
}

const API_TARGET = { id: 'tgt_api', tenant_id: 'ten_r', kind: 'url', value: 'https://api.example.test/v1/orders', target_group_id: 'tg_r' };

describe('declared API paths only get GET/HEAD-only checks', () => {
  for (const scenario of ['waf.inspection_limit.safe', 'waf.fingerprint.safe']) {
    it(`refuses ${scenario} on a declared API URL with a state-change reason`, () => {
      const api = selectEntryPathCheck({ relation: { relation_kind: 'declared_api_url' }, entryTarget: API_TARGET, scenario, catalog: CHECK_CATALOG });
      assert.equal(api.check, null);
      assert.equal(api.reason, 'api_path_state_change_risk');
      const login = selectEntryPathCheck({ relation: { relation_kind: 'declared_login_url' }, entryTarget: API_TARGET, scenario, catalog: CHECK_CATALOG });
      assert.equal(login.reason, 'login_path_state_change_risk');
    });
  }

  it('still selects the GET/HEAD-only API marker check for the generic marker scenario', () => {
    const selected = selectEntryPathCheck({ relation: { relation_kind: 'declared_api_url' }, entryTarget: API_TARGET, scenario: 'marker', catalog: CHECK_CATALOG });
    assert.equal(selected.check?.check_id, 'waf.entry_path_api_marker.safe');
  });
});

describe('signed vendor denial on the permitted baseline of a marker leg', () => {
  it('records the baseline signature and classifies a must-not-be-reachable path as consistent enforcement', async () => {
    const probe = await runEntryPathMarkerProbe({
      url: 'https://app.example.test/login',
      entry_path_scenario: 'declared_login_path',
      marker_class: 'sqli',
      fetchFn: async () => stubResponse(403, CLOUDFLARE_CHALLENGE),
    });
    assert.equal(probe.permitted_baseline.health, 'unhealthy');
    assert.equal(probe.permitted_baseline.denial_signature?.id, 'cloudflare_challenge');
    const derived = deriveAttemptObservation({ external_result: 'not_run', probe_metadata: { profile_kind: 'waf_class_marker_probe', ...probe } });
    assert.equal(derived.observation, 'explicit_denial_observed');
    assert.equal(derived.denial_signature.id, 'cloudflare_challenge');
    const relation = { status: 'active', relation_kind: 'declared_login_url', expected_behavior: 'must_not_be_reachable', required_layers: [] };
    const classified = classifyPathValidationItem({ relation, observation: derived.observation, enforcement: derived.enforcement });
    assert.equal(classified.outcome, 'consistent_enforcement');
  });

  it('keeps an unsigned 403 baseline on a must-not-be-reachable path as reachability exposure', async () => {
    const probe = await runEntryPathMarkerProbe({
      url: 'https://app.example.test/login',
      entry_path_scenario: 'declared_login_path',
      fetchFn: async () => stubResponse(403),
    });
    assert.equal(probe.permitted_baseline.denial_signature, null);
    const derived = deriveAttemptObservation({ external_result: 'not_run', probe_metadata: { profile_kind: 'waf_class_marker_probe', ...probe } });
    assert.equal(derived.observation, 'response_observed');
    const relation = { status: 'active', relation_kind: 'declared_login_url', expected_behavior: 'must_not_be_reachable', required_layers: [] };
    assert.equal(classifyPathValidationItem({ relation, observation: derived.observation }).outcome, 'reachability_exposure');
  });
});

describe('body-based vendor signatures are read from a bounded body prefix', () => {
  const fetchFn = async (url, init) => (carriesMarker(url, init) && init.method !== 'HEAD'
    ? stubResponse(200, {}, F5_BLOCK_PAGE)
    : stubResponse(200, {}, '<html><body>Welcome</body></html>'));

  it('grades an F5 ASM block page served with HTTP 200 as a block on the class-marker probe', async () => {
    const result = await runWafClassMarkerProbe({ url: 'https://app.example.test/', marker_class: 'ssrf', fetchFn });
    assert.notEqual(result.posture, 'exposed');
    assert.ok(result.marker_results.some((row) => row.blocked && row.denial_signature?.vendor === 'f5'));
    assert.equal(JSON.stringify(result).includes('requested URL was rejected'), false);
  });

  it('never grades the F5 200 block page as allowed on the entry-path probe', async () => {
    const result = await runEntryPathMarkerProbe({ url: 'https://app.example.test/login', entry_path_scenario: 'declared_login_path', fetchFn });
    assert.ok(result.marker_results.filter((row) => row.method === 'GET' && !row.reference_variation).every((row) => row.blocked));
    assert.notEqual(result.enforcement, 'not_enforced');
  });

  it('matches a customer-declared block signature only when supplied', async () => {
    const declaredFetch = async (url, init) => (carriesMarker(url, init)
      ? stubResponse(406, { 'x-block-ref': 'edge-policy' })
      : stubResponse(200));
    const undeclared = await runWafClassMarkerProbe({ url: 'https://app.example.test/', marker_class: 'ssrf', fetchFn: declaredFetch });
    assert.equal(undeclared.posture, 'inconclusive');
    const declared = await runWafClassMarkerProbe({
      url: 'https://app.example.test/',
      marker_class: 'ssrf',
      fetchFn: declaredFetch,
      declared_block_signature: { status_code: 406, header: { name: 'x-block-ref', value: 'edge-policy' } },
    });
    assert.equal(declared.posture, 'protected');
  });
});

describe('WAF enforcement probe reads a bounded GET body', () => {
  it('counts an F5 block page served with HTTP 200 as blocked, not a monitor-only leak', async () => {
    const methods = [];
    const outcome = await probeWafEnforcement(
      { constraints: { timeout_ms: 1000 }, target: { kind: 'url', value: 'https://app.example.test/' }, probe_profile: { kind: 'waf_enforcement_probe', marker: 'astranull-marker' } },
      { fetchFn: async (_url, init) => { methods.push(init.method); return stubResponse(200, {}, F5_BLOCK_PAGE); } },
    );
    assert.deepEqual(methods, ['GET']);
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.monitor_only_leak, false);
    assert.equal(outcome.metadata.denial_signature.vendor, 'f5');
  });
});

describe('evasion check versions', () => {
  it('bumps every waf.evasion_*.safe check to 1.1.0 for the signature-based grading', () => {
    const evasion = CHECK_CATALOG.filter((check) => /^waf\.evasion_.+\.safe$/.test(check.check_id));
    assert.equal(evasion.length, 41);
    assert.ok(evasion.every((check) => check.version === '1.1.0'));
  });
});
