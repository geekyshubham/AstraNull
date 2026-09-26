import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, customerSelectableChecks, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { withCheckSection } from '../../src/contracts/validationScanManagement.mjs';
import {
  OTHER_SECTION_LABEL,
  checkExclusionReason,
  checkProbeSummary,
  checkTargetCoverage,
  filterChecks,
  groupChecksBySection,
  selectableChecks,
  summarizeSelection,
} from '../../apps/web/react/src/lib/check-picker.mjs';

const fqdn = { id: 'tgt_fqdn', kind: 'fqdn', value: 'edge.example.test' };
const ip = { id: 'tgt_ip', kind: 'ip', value: '203.0.113.9' };
const url = { id: 'tgt_url', kind: 'url', value: 'https://edge.example.test/health' };

const safeFqdn = {
  check_id: 'dns.safe',
  name: 'DNS posture',
  safety_class: 'safe',
  evidence_tier: 'E2',
  section_id: 'A3',
  section_label: 'DNS Service Exhaustion',
  supported_targets: ['fqdn', 'dns'],
  probe_profile: { kind: 'dns_wire_query', max_requests: 2, timeout_ms: 5000 },
};
const safeAny = {
  check_id: 'l7.safe',
  name: 'HTTP posture',
  safety_class: 'safe',
  evidence_tier: 'E3',
  vector_family: 'l7_http',
  supported_targets: [],
  probe_profile: { kind: 'http_head', max_requests: 5, timeout_ms: 5000 },
};
const noSection = {
  check_id: 'misc.safe',
  name: 'Misc',
  safety_class: 'safe',
  evidence_tier: 'E1',
  supported_targets: ['ip'],
  probe_profile: { kind: 'metadata_marker', max_requests: 1 },
};
const socGated = { check_id: 'waf.soc', name: 'SOC only', safety_class: 'soc_gated', risk_class: 'soc_gated', evidence_tier: 'E4', supported_targets: ['fqdn'] };
const monitorOnly = { check_id: 'mon.only', name: 'Monitor', safety_class: 'safe', evidence_tier: 'E5', supported_targets: ['fqdn'] };
const notRunnable = { check_id: 'hidden.safe', name: 'Hidden', safety_class: 'safe', evidence_tier: 'E3', safety_constraints: { customer_runnable: false } };

describe('check picker selection rules', () => {
  it('excludes SOC-gated, monitor-only, and non-runnable checks with counts', () => {
    const result = selectableChecks([safeFqdn, safeAny, socGated, monitorOnly, notRunnable, noSection]);
    assert.deepEqual(result.checks.map((check) => check.check_id), ['dns.safe', 'l7.safe', 'misc.safe']);
    assert.deepEqual(result.excluded, { soc_gated: 1, monitor_only: 1, not_customer_runnable: 1, total: 3 });
    assert.equal(checkExclusionReason(socGated), 'soc_gated');
    assert.equal(checkExclusionReason(monitorOnly), 'monitor_only');
    assert.equal(checkExclusionReason(notRunnable), 'not_customer_runnable');
    assert.equal(checkExclusionReason(safeAny), null);
  });

  it('never exposes a catalog check the backend would refuse as SOC-gated', () => {
    const catalog = customerSelectableChecks(CHECK_CATALOG).map(withCheckSection);
    const { checks } = selectableChecks(catalog);
    assert.ok(checks.length > 0);
    for (const check of checks) {
      assert.equal(isCustomerRunnable(check), true, check.check_id);
      assert.equal(check.safety_class, 'safe', check.check_id);
      assert.notEqual(check.evidence_tier, 'E5', check.check_id);
    }
    assert.ok(catalog.some((check) => !isCustomerRunnable(check)), 'catalog fixture should contain a SOC-gated check');
  });

  it('groups by taxonomy section, falls back to vector family, and keeps Other last', () => {
    const groups = groupChecksBySection([noSection, safeAny, safeFqdn]);
    assert.deepEqual(groups.map((group) => group.label), ['DNS Service Exhaustion', 'L7 Http', OTHER_SECTION_LABEL]);
    assert.deepEqual(groups[2].checks.map((check) => check.check_id), ['misc.safe']);
  });

  it('computes target coverage from supported target kinds', () => {
    assert.deepEqual(checkTargetCoverage(safeFqdn, [fqdn, ip, url]), { supported: 1, total: 3, supportedTargetIds: ['tgt_fqdn'] });
    assert.equal(checkTargetCoverage(safeAny, [fqdn, ip, url]).supported, 3);
    assert.equal(checkTargetCoverage(noSection, [fqdn, url]).supported, 0);
  });

  it('summarizes planned steps and the request upper bound for exact and group scope', () => {
    const groupSummary = summarizeSelection({ checks: [safeFqdn, safeAny, noSection], selectedIds: ['dns.safe', 'l7.safe', 'misc.safe'], targets: [fqdn, ip, url] });
    assert.equal(groupSummary.selectedCount, 3);
    assert.equal(groupSummary.stepCount, 1 + 3 + 1);
    assert.equal(groupSummary.requestUpperBound, 2 * 1 + 5 * 3 + 1 * 1);
    assert.deepEqual(groupSummary.incompatible, []);
    assert.equal(groupSummary.targetCount, 3);

    const exactSummary = summarizeSelection({ checks: [safeFqdn, noSection], selectedIds: ['dns.safe', 'misc.safe'], targets: [fqdn, ip], targetId: 'tgt_fqdn' });
    assert.equal(exactSummary.stepCount, 1);
    assert.equal(exactSummary.requestUpperBound, 2);
    assert.deepEqual(exactSummary.incompatible.map((row) => row.check_id), ['misc.safe']);
    assert.equal(exactSummary.targetCount, 1);
  });

  it('reports an unknown request bound when a selected check has no max_requests', () => {
    const unbounded = { ...safeAny, check_id: 'unbounded.safe', probe_profile: { kind: 'ops_readiness' } };
    const summary = summarizeSelection({ checks: [safeAny, unbounded], selectedIds: ['l7.safe', 'unbounded.safe'], targets: [fqdn] });
    assert.equal(summary.stepCount, 2);
    assert.equal(summary.requestUpperBound, null);
    assert.deepEqual(checkProbeSummary(unbounded), { kind: 'ops_readiness', maxRequests: null, timeoutMs: null });
  });

  it('filters by id, name, section, and probe kind', () => {
    const checks = [safeFqdn, safeAny, noSection];
    assert.deepEqual(filterChecks(checks, 'dns').map((check) => check.check_id), ['dns.safe']);
    assert.deepEqual(filterChecks(checks, 'HTTP posture').map((check) => check.check_id), ['l7.safe']);
    assert.deepEqual(filterChecks(checks, 'metadata_marker').map((check) => check.check_id), ['misc.safe']);
    assert.equal(filterChecks(checks, '').length, 3);
  });
});
