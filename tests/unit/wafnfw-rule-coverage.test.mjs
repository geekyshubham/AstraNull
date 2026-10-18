import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import { targetRuleCoverage } from '../../src/services/ruleCoverage.mjs';
import { CONTROL_DECLARATIONS_METADATA_KEY } from '../../src/contracts/controlDeclarations.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const byId = (coverage, id) => coverage.categories.find((row) => row.id === id);

describe('catalog rule coverage', () => {
  it('assigns expected assurance for the required WAF and NFW categories', () => {
    const coverage = catalogRuleCoverage();
    assert.equal(coverage.version, 'rule-coverage.v1');
    assert.ok(['VERDICT_CAPABLE_PROBE_KINDS', 'observation_only_complement'].includes(coverage.verdict_capable_from));
    assert.equal(byId(coverage, 'custom_canary').assurance, 'observation');
    assert.equal(byId(coverage, 'scanner_detection').assurance, 'verdict');
    assert.equal(byId(coverage, 'sqli').assurance, 'verdict');
    assert.equal(byId(coverage, 'http_method_policy').assurance, 'verdict');
    assert.equal(byId(coverage, 'request_body').assurance, 'soc_only');
    assert.equal(byId(coverage, 'icmp_policy').assurance, 'not_assessable');
    assert.match(byId(coverage, 'icmp_policy').not_assessable_reason, /ICMP/);
    assert.equal(byId(coverage, 'egress_filtering').assurance, 'out_of_scope');
    assert.match(byId(coverage, 'egress_filtering').out_of_scope_reason, /inside the network/);
    assert.equal(byId(coverage, 'inbound_tcp_deny').assurance, 'violation_only');
    assert.equal(byId(coverage, 'connection_limits').assurance, 'violation_only');
    assert.equal(byId(coverage, 'allowlists_geo').assurance, 'violation_only');
    assert.match(byId(coverage, 'allowlists_geo').assurance_reason, /Needs at least two registered probe perspectives/);
    assert.equal(byId(coverage, 'rate_limiting').assurance, 'verdict');
    const gatedIds = [
      'waf.rate_limit_canary.validation',
      'nfw.declared_deny_tcp.safe',
      'nfw.declared_deny_udp.safe',
      'nfw.connection_limit.safe',
      'nfw.origin_lockdown.safe',
      'nfw.perspective_allowlist.safe',
    ];
    for (const gid of gatedIds) {
      const found = coverage.categories.flatMap((cat) => cat.checks).find((chk) => chk.check_id === gid);
      assert.ok(found, `gated check ${gid} should be present`);
      assert.notEqual(found.assurance, 'not_assessable', `${gid} should not be not_assessable`);
      assert.ok(Array.isArray(found.required_declarations) && found.required_declarations.length > 0);
    }
    assert.equal(byId(coverage, 'rfi').assurance, 'missing');
    assert.match(byId(coverage, 'rfi').assurance_reason, /Remote-file-inclusion and CVE exploit markers/);
    assert.equal(byId(coverage, 'cve_virtual_patching').assurance, 'missing');
    assert.match(byId(coverage, 'cve_virtual_patching').assurance_reason, /Remote-file-inclusion and CVE exploit markers/);
  });
});

describe('target rule coverage', () => {
  it('selects the latest immutable publication independent of store order and respects tenant, run and cutoff scope', () => {
    freshStore();
    const store = getStore();
    const nowMs = Date.parse('2026-10-13T00:00:00.000Z');
    store.testRuns = [{ id: 'run_latest_coverage', tenant_id: 'ten_demo', target_id: 'tgt_1',
      check_id: 'waf.sqli_managed_marker.safe', status: 'completed',
      started_at: '2026-10-12T00:00:00.000Z', completed_at: '2026-10-12T00:01:00.000Z' }];
    const publication = (extra) => ({ id: 'v_old', tenant_id: 'ten_demo', test_run_id: 'run_latest_coverage',
      verdict: 'protected', created_at: '2026-10-12T00:01:00.000Z', ...extra });
    const verdicts = [
      publication({}),
      publication({ id: 'v_new_a', verdict: 'protected', created_at: '2026-10-12T00:02:00.000Z' }),
      publication({ id: 'v_new_z', verdict: 'inconclusive', created_at: '2026-10-12T00:02:00.000Z' }),
      publication({ id: 'v_foreign_tenant', tenant_id: 'ten_other', created_at: '2026-10-12T00:03:00.000Z' }),
      publication({ id: 'v_foreign_run', test_run_id: 'run_other', created_at: '2026-10-12T00:03:00.000Z' }),
      publication({ id: 'v_future', created_at: '2026-10-14T00:00:00.000Z' }),
      publication({ id: 'v_late_ingestion', created_at: '2026-10-12T00:04:00.000Z', ingested_at: '2026-10-14T00:00:00.000Z' }),
    ];
    for (const ordered of [verdicts, [...verdicts].reverse(), [...verdicts.slice(3), ...verdicts.slice(0, 3)]]) {
      store.verdicts = ordered;
      const sqli = byId(targetRuleCoverage({ tenantId: 'ten_demo' }, 'tgt_1', { nowMs }), 'sqli');
      assert.equal(sqli.checks.find((row) => row.check_id === 'waf.sqli_managed_marker.safe').verdict, 'inconclusive');
      assert.equal(sqli.status, 'inconclusive');
    }
  });

  it('returns pass, fail and needs_declaration from a fake store', () => {
    freshStore();
    const store = getStore();
    const target = store.targets.find((row) => row.id === 'tgt_1');
    target.metadata = {
      [CONTROL_DECLARATIONS_METADATA_KEY]: {
        version: 1,
        waf: { rate_limit_canary: { path: '/canary', method: 'GET', threshold: 3, window_seconds: 10 } },
      },
    };
    const now = Date.parse('2026-10-13T00:00:00.000Z');
    store.testRuns.push(
      {
        id: 'run_pass',
        tenant_id: 'ten_demo',
        target_id: 'tgt_1',
        check_id: 'waf.sqli_managed_marker.safe',
        status: 'completed',
        started_at: '2026-10-12T00:00:00.000Z',
        completed_at: '2026-10-12T00:01:00.000Z',
      },
      {
        id: 'run_fail',
        tenant_id: 'ten_demo',
        target_id: 'tgt_1',
        check_id: 'waf.http_method_policy_marker.safe',
        status: 'completed',
        started_at: '2026-10-12T00:00:00.000Z',
        completed_at: '2026-10-12T00:01:00.000Z',
      },
    );
    store.verdicts.push(
      { id: 'v_pass', tenant_id: 'ten_demo', test_run_id: 'run_pass', verdict: 'protected', created_at: '2026-10-12T00:01:00.000Z' },
      { id: 'v_fail', tenant_id: 'ten_demo', test_run_id: 'run_fail', verdict: 'exposed', created_at: '2026-10-12T00:01:00.000Z' },
    );
    const coverage = targetRuleCoverage({ tenantId: 'ten_demo' }, 'tgt_1', { nowMs: now });
    assert.equal(coverage.target_id, 'tgt_1');
    assert.equal(byId(coverage, 'sqli').status, 'covered_pass');
    assert.equal(byId(coverage, 'custom_canary').status, 'inconclusive');
    assert.equal(byId(coverage, 'custom_canary').checks.find((row) => row.check_id === 'waf.http_method_policy_marker.safe').verdict, 'exposed');
    assert.equal(byId(coverage, 'inbound_tcp_deny').status, 'needs_declaration');
    assert.deepEqual(byId(coverage, 'inbound_tcp_deny').missing_declarations, ['network_policy']);
    assert.equal(byId(coverage, 'egress_filtering').status, 'out_of_scope');
    assert.equal(byId(coverage, 'icmp_policy').status, 'not_assessable');
    assert.equal(targetRuleCoverage({ tenantId: 'ten_other' }, 'tgt_1'), null);
  });
});
