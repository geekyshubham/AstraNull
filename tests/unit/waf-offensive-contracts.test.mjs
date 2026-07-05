import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertApprovedOffensiveSuiteIds,
  listOffensiveSuites,
  normalizeOffensiveSuiteResult,
  offensiveAuthorizationPackComplete,
  validateOffensiveRequestIntake,
} from '../../src/contracts/wafOffensive.mjs';
import { normalizeSocOffensiveWafValidationRequest } from '../../src/contracts/wafPosture.mjs';

describe('waf offensive contracts', () => {
  it('lists curated offensive suites', () => {
    const suites = listOffensiveSuites();
    assert.ok(suites.length >= 8);
    assert.ok(suites.some((s) => s.suite_id === 'sqli_offensive'));
    assert.equal(suites.find((s) => s.suite_id === 'sqli_offensive')?.risk_class, 'soc_gated');
  });

  it('rejects customer intake without scope confirmation', () => {
    const result = validateOffensiveRequestIntake({
      waf_asset_id: 'waf_1',
      objective: 'Prove SQLi blocking',
      requested_suites: ['sqli_offensive'],
      emergency_contacts: ['ops@example.invalid'],
    });
    assert.equal(result.error, 'scope_confirmation_required');
  });

  it('rejects raw payload fields on intake', () => {
    const result = validateOffensiveRequestIntake({
      waf_asset_id: 'waf_1',
      objective: 'Prove SQLi blocking',
      requested_suites: ['sqli_offensive'],
      emergency_contacts: ['ops@example.invalid'],
      scope_confirmation: true,
      exploit_payload: 'bad',
    });
    assert.ok(['unsafe_offensive_request', 'unsafe_waf_evidence'].includes(result.error));
  });

  it('normalizes SOC offensive validation profile', () => {
    const profile = normalizeSocOffensiveWafValidationRequest({
      waf_asset_id: 'waf_1',
      offensive_request_id: 'wof_1',
      modes: ['sqli_offensive', 'xss_offensive'],
      max_requests: 20,
    });
    assert.equal(profile.probe_profile.risk_class, 'soc_gated');
    assert.equal(profile.probe_profile.execution_class, 'offensive_suite');
    assert.deepEqual(profile.modes, ['sqli_offensive', 'xss_offensive']);
  });

  it('tracks authorization pack completeness', () => {
    const suites = assertApprovedOffensiveSuiteIds(['sqli_offensive', 'xss_offensive']);
    assert.deepEqual(suites, ['sqli_offensive', 'xss_offensive']);
    const complete = offensiveAuthorizationPackComplete({
      artifacts: [
        { type: 'customer_authorization_letter', status: 'accepted' },
        { type: 'target_ownership_confirmation', status: 'accepted' },
        { type: 'emergency_contacts', status: 'accepted' },
        { type: 'stop_criteria', status: 'accepted' },
        { type: 'waf_offensive_test_plan', status: 'accepted' },
        { type: 'staging_isolation_confirmation', status: 'accepted' },
      ],
    });
    assert.equal(complete, true);
  });

  it('normalizes suite results without raw payloads', () => {
    const result = normalizeOffensiveSuiteResult(
      {
        observed_action: 'block',
        passed: true,
        confidence: 0.92,
        evidence_summary: { block_page_signature_id: 'cf-403-a' },
        probes_attempted: 10,
        blocked_count: 10,
      },
      'sqli_offensive',
    );
    assert.equal(result.test_material_type, 'soc_gated_offensive_suite');
    assert.equal(result.scenario_family, 'sqli_offensive');
    assert.equal(result.passed, true);
  });
});