import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CHECK_SAFETY_SCOPE_TABS,
  countChecksBySafetyScope,
  filterChecksByFamilyTab,
  filterChecksBySafetyScope,
  filterChecksCatalog,
  isSocGatedCheck
} from '../../apps/web/react/src/lib/checks-helpers.ts';

const SAMPLE_CHECKS = [
  { check_id: 'origin.direct_bypass.safe', safety_class: 'safe', vector_family: 'origin' },
  { check_id: 'waf.origin_bypass.safe', safety_class: 'safe', vector_family: 'waf', probe_profile: { scenario_family: 'origin_bypass' } },
  { check_id: 'l3.forbidden_tcp_port.safe', safety_class: 'safe', vector_family: 'l3_l4' },
  { check_id: 'dns.authoritative_response.safe', safety_class: 'safe', vector_family: 'dns' },
  { check_id: 'l7.waf_marker_rule.safe', safety_class: 'safe', vector_family: 'l7' },
  { check_id: 'waf.fingerprint.safe', safety_class: 'safe', vector_family: 'waf' },
  { check_id: 'protocol.http2_readiness.safe', safety_class: 'safe', vector_family: 'protocol' },
  { check_id: 'high_scale.dns_high_query.request_only', safety_class: 'soc_gated', vector_family: 'high_scale' },
  { check_id: 'ops.kill_switch_drill.request_only', safety_class: 'soc_gated', vector_family: 'operations' }
];

describe('checks react helpers', () => {
  it('exposes All/Safe/SOC safety scope tabs', () => {
    assert.deepEqual(CHECK_SAFETY_SCOPE_TABS.map((tab) => tab.id), ['all', 'safe', 'soc']);
  });

  it('counts catalog checks by safety scope from API-shaped rows', () => {
    const counts = countChecksBySafetyScope(SAMPLE_CHECKS);
    assert.equal(counts.all, SAMPLE_CHECKS.length);
    assert.equal(counts.safe, 7);
    assert.equal(counts.soc, 2);
  });

  it('filters safe and soc scopes independently', () => {
    assert.equal(filterChecksBySafetyScope(SAMPLE_CHECKS, 'safe').length, 7);
    assert.equal(filterChecksBySafetyScope(SAMPLE_CHECKS, 'soc').length, 2);
    assert.equal(filterChecksBySafetyScope(SAMPLE_CHECKS, 'all').length, SAMPLE_CHECKS.length);
  });

  it('includes waf origin-bypass checks in the origin-bypass family tab', () => {
    const originBypass = filterChecksByFamilyTab(SAMPLE_CHECKS, 'origin-bypass');
    assert.ok(originBypass.some((check) => check.check_id === 'origin.direct_bypass.safe'));
    assert.ok(originBypass.some((check) => check.check_id === 'waf.origin_bypass.safe'));
  });

  it('includes waf checks in the l7api family tab', () => {
    const l7api = filterChecksByFamilyTab(SAMPLE_CHECKS, 'l7api');
    assert.ok(l7api.some((check) => check.check_id === 'l7.waf_marker_rule.safe'));
    assert.ok(l7api.some((check) => check.check_id === 'waf.fingerprint.safe'));
  });

  it('returns DNS, L3/L4, and high-scale family slices from vector_family', () => {
    assert.equal(filterChecksByFamilyTab(SAMPLE_CHECKS, 'dns').length, 1);
    assert.equal(filterChecksByFamilyTab(SAMPLE_CHECKS, 'l3l4').length, 1);
    assert.equal(filterChecksByFamilyTab(SAMPLE_CHECKS, 'high-scale').length, 2);
  });

  it('keeps custom family tab empty as an intentional boundary', () => {
    assert.deepEqual(filterChecksByFamilyTab(SAMPLE_CHECKS, 'custom'), []);
  });

  it('applies safety scope before family tab filtering', () => {
    const scoped = filterChecksCatalog(SAMPLE_CHECKS, 'high-scale', 'safe');
    assert.equal(scoped.length, 0);
    const socHighScale = filterChecksCatalog(SAMPLE_CHECKS, 'high-scale', 'soc');
    assert.equal(socHighScale.length, 2);
    assert.ok(isSocGatedCheck(socHighScale[0]));
  });
});