// Integration: the protection-validation workflow through the real dev-json server (gate, routes, PV-04/05/06 seams).
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { resolveDevProtectionRetestAuthorization } from '../../src/services/protectionValidationRetest.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TENANT = 'ten_demo';
const DISABLED_TENANT = 'ten_pv_off';
const SOURCE = 'astranull-signed-public-worker';
const DECLARED = '2026-09-01T00:00:00.000Z';

const admin = (tenant = TENANT) => demoHeaders('admin', tenant, 'usr_admin');
const viewer = (tenant = TENANT) => demoHeaders('viewer', tenant, 'usr_viewer');

let server;
let baseUrl;

function addTarget(partial, { verified = true } = {}) {
  const store = getStore();
  store.targets.push({ tenant_id: TENANT, target_group_id: 'tg_1', created_at: DECLARED, deleted_at: null, ...partial });
  if (!verified) return;
  store.targetVerifications.push({
    id: `tv_${partial.id}`,
    tenant_id: partial.tenant_id ?? TENANT,
    target_id: partial.id,
    state: 'dns_verified',
    source_kind: 'dns_txt',
    source_ref: { dns_challenge_id: `dns_${partial.id}` },
    transitioned_at: DECLARED,
    transitioned_by: 'system',
  });
}

let eventSeq = 0;
function addTlsRun(id, { target = 'tgt_fw', day, tls = true, samples = 2, worker = 'worker_pool_1' }) {
  const store = getStore();
  store.testRuns.push({
    id, tenant_id: TENANT, target_group_id: 'tg_1', target_id: target, check_id: 'tls.full_audit.safe', status: 'verdicted',
    producer_kind: 'signed_probe', check_version: '1.0.0', scenario_version: null, created_at: `${day}T00:00:00.000Z`,
    completed_at: `${day}T00:10:00.000Z`, provenance_json: {},
  });
  store.verdicts.push({ id: `verdict_${id}`, tenant_id: TENANT, test_run_id: id, verdict: 'pass', evidence_ids: [], created_at: `${day}T00:10:00.000Z` });
  for (let index = 0; index < samples; index += 1) {
    eventSeq += 1;
    store.events.push({
      id: `evt_pv_${eventSeq}`, tenant_id: TENANT, test_run_id: id, target_id: target, check_id: 'tls.full_audit.safe',
      signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: `${day}T00:0${index}:00.000Z`,
      metadata: {
        profile_kind: 'tls_audit',
        external_result: tls ? 'blocked' : 'timeout',
        probe_worker_id: worker,
        safety_attestation: { requests_sent: 1, duration_ms: 4 },
        ...(tls ? { tls_protocol: 'TLSv1.3' } : { error_class: 'ETIMEDOUT' }),
      },
    });
  }
}

function seed() {
  freshStore();
  const store = getStore();
  store.tenants.push({ id: DISABLED_TENANT, name: 'Gate off' });
  store.targetVerifications = store.targetVerifications ?? [];
  addTarget({ id: 'tgt_app', kind: 'fqdn', value: 'app.example.test' });
  addTarget({ id: 'tgt_alt', kind: 'fqdn', value: 'alt.example.test' });
  addTarget({ id: 'tgt_fw', kind: 'fqdn', value: 'fw.example.test' });
}

before(async () => {
  const env = {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_RATE_LIMIT_DISABLED: '1',
    ASTRANULL_PROTECTION_VALIDATION_ENABLED: '1',
    ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: JSON.stringify({ [DISABLED_TENANT]: false }),
    ASTRANULL_APPROVED_PROBE_SOURCES: '',
  };
  server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
});

beforeEach(() => {
  seed();
});

async function declarePaths() {
  const primary = await request(baseUrl, 'POST', '/v1/targets/tgt_app/entry-paths', {
    headers: admin(),
    body: { entry_target_id: 'tgt_app', relation_kind: 'primary_route', owner: 'App team', purpose: 'Storefront', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] },
  });
  assert.equal(primary.status, 201, JSON.stringify(primary.json));
  const alternate = await request(baseUrl, 'POST', '/v1/targets/tgt_app/entry-paths', {
    headers: admin(),
    body: { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname', owner: 'App team', purpose: 'Legacy hostname', expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'] },
  });
  assert.equal(alternate.status, 201, JSON.stringify(alternate.json));
  return { primary: primary.json, alternate: alternate.json };
}

describe('protection validation over the dev HTTP surface', () => {
  it('gates every route per tenant and advertises the feature', async () => {
    const features = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: admin() });
    assert.equal(features.json.protection_validation, true);
    const off = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: admin(DISABLED_TENANT) });
    assert.equal(off.json.protection_validation, false);
    for (const path of ['/v1/targets/tgt_app/entry-paths', '/v1/firewall-expectations', '/v1/entry-path-comparisons', '/v1/reports/protection-validation']) {
      const res = await request(baseUrl, 'GET', path, { headers: admin(DISABLED_TENANT) });
      assert.equal(res.status, 404, path);
      assert.equal(res.json.error, 'protection_validation_disabled', path);
    }
  });

  it('declares paths, plans passively, and serves the per-path matrix with target values', async () => {
    const { primary, alternate } = await declarePaths();
    const runsBefore = getStore().testRuns.length;
    const plan = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', {
      headers: admin(),
      body: {
        mode: 'plan', anchor_target_id: 'tgt_app', primary_entry_path_id: primary.id,
        entry_path_ids: [primary.id, alternate.id], expectation: { scenario: 'waf.ssrf_marker.safe', layer_outcomes: { waf: 'enforce' } },
      },
    });
    assert.equal(plan.status, 200, JSON.stringify(plan.json));
    assert.equal(plan.json.mode, 'plan');
    assert.match(plan.json.plan_digest, /^[a-f0-9]{64}$/);
    assert.equal(getStore().testRuns.length, runsBefore, 'plan never starts runs');

    const matrix = await request(baseUrl, 'GET', '/v1/targets/tgt_app/protection-validation', { headers: viewer() });
    assert.equal(matrix.status, 200, JSON.stringify(matrix.json));
    assert.equal(matrix.json.connectors_required, false);
    assert.equal(matrix.json.paths.length, 2);
    const alt = matrix.json.paths.find((row) => row.entry_path_id === alternate.id);
    assert.equal(alt.entry_target_value, 'alt.example.test');
    assert.equal(alt.outcome, 'not_tested');
    assert.deepEqual(alt.layers.map((layer) => layer.layer), ['waf', 'cdn_edge', 'network_firewall', 'ddos']);
    assert.ok(alt.layers.every((layer) => layer.configuration?.evidence_role === 'explanation_only'));
    assert.equal(getStore().testRuns.length, runsBefore, 'matrix read is passive');
  });

  it('starts a reviewed comparison, records its evaluation, and stops through the cancel route', async () => {
    const { primary, alternate } = await declarePaths();
    const request0 = {
      anchor_target_id: 'tgt_app', primary_entry_path_id: primary.id, entry_path_ids: [primary.id, alternate.id],
      expectation: { scenario: 'waf.ssrf_marker.safe', layer_outcomes: { waf: 'enforce' } },
    };
    const plan = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', { headers: admin(), body: { ...request0, mode: 'plan' } });
    const mismatch = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', {
      headers: admin(), body: { ...request0, mode: 'start', reviewed_plan_digest: 'f'.repeat(64) },
    });
    assert.equal(mismatch.status, 409);
    assert.equal(mismatch.json.error, 'reviewed_plan_mismatch');
    const started = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', {
      headers: admin(), body: { ...request0, mode: 'start', reviewed_plan_digest: plan.json.plan_digest },
    });
    assert.equal(started.status, 202, JSON.stringify(started.json));
    assert.equal(started.json.mode, 'start');
    const comparisonId = started.json.id;
    await new Promise((resolve) => setTimeout(resolve, 50));
    const view = await request(baseUrl, 'GET', `/v1/entry-path-comparisons/${comparisonId}`, { headers: viewer() });
    assert.equal(view.status, 200);
    assert.ok(view.json.items.every((item) => 'test_run_id' in item));
    if (view.json.status === 'running') {
      const stop = await request(baseUrl, 'POST', `/v1/entry-path-comparisons/${comparisonId}/cancel`, { headers: admin(), body: { reason: 'operator stop' } });
      assert.equal(stop.status, 200, JSON.stringify(stop.json));
      assert.equal(stop.json.status, 'cancelled');
    } else {
      const stop = await request(baseUrl, 'POST', `/v1/entry-path-comparisons/${comparisonId}/cancel`, { headers: admin(), body: {} });
      assert.equal(stop.status, 409);
      assert.equal(stop.json.error, 'not_cancellable');
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    const finished = await request(baseUrl, 'GET', `/v1/entry-path-comparisons/${comparisonId}`, { headers: viewer() });
    assert.ok(['completed', 'cancelled'].includes(finished.json.status));
    assert.match(finished.json.evaluation_id ?? '', /^pvc_/, 'finished comparison is recorded through PV-03');
    const recorded = getStore().protectionComparisonEvaluations.find((row) => row.id === finished.json.evaluation_id);
    assert.equal(recorded.kind, 'path_validation');
    assert.equal(recorded.provenance.comparison_id, comparisonId);
    assert.match(recorded.provenance.expectation_id, /^pvx_/);
    const viewerStop = await request(baseUrl, 'POST', `/v1/entry-path-comparisons/${comparisonId}/cancel`, { headers: viewer(), body: {} });
    assert.equal(viewerStop.status, 403);
  });

  it('captures, evaluates, and reports a firewall change with PV-05 semantics and derived findings', async () => {
    const expectation = await request(baseUrl, 'POST', '/v1/firewall-expectations', {
      headers: admin(),
      body: { destination_target_id: 'tgt_fw', protocol: 'tcp', port: 443, expected: 'allow', source_perspective: SOURCE, change_id: 'CHG-2001', owner: 'Network team' },
    });
    assert.equal(expectation.status, 201, JSON.stringify(expectation.json));
    addTlsRun('run_pv_pre', { day: '2026-10-01', tls: true });
    addTlsRun('run_pv_post', { day: '2026-10-03', tls: false });
    const fetchBefore = globalThis.fetch;
    const baseline = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: admin(), body: { change_id: 'CHG-2001', expectation_ids: [expectation.json.id], test_run_ids: ['run_pv_pre'] },
    });
    assert.equal(baseline.status, 201, JSON.stringify(baseline.json));
    assert.equal(baseline.json.entries[0].classifier_version, 'firewall-acceptance-v3');
    assert.ok(baseline.json.entries[0].observations.every((obs) => obs.observation_class === 'service_response_observed'));
    assert.equal(baseline.json.digest_verified, true);
    const replay = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: admin(), body: { change_id: 'CHG-2001', expectation_ids: [expectation.json.id], test_run_ids: ['run_pv_pre'] },
    });
    assert.equal(replay.status, 200);
    assert.equal(replay.json.id, baseline.json.id);

    const findingsBefore = getStore().findings.length;
    const comparison = await request(baseUrl, 'POST', '/v1/firewall-comparisons', {
      headers: admin(), body: { baseline_id: baseline.json.id, post_test_run_ids: ['run_pv_post'] },
    });
    assert.equal(comparison.status, 201, JSON.stringify(comparison.json));
    const item = comparison.json.items[0];
    assert.equal(item.status, 'regression');
    assert.equal(item.gap_kind, 'required_service_newly_unavailable');
    assert.equal(comparison.json.readiness_effect, 'none');
    assert.equal(comparison.json.classifier_version, 'firewall-acceptance-v3');
    assert.match(comparison.json.statement.headline, /sampled public-ingress/i);
    assert.equal(globalThis.fetch, fetchBefore);

    const findings = getStore().findings.filter((row) => row.source === 'protection_validation');
    assert.equal(getStore().findings.length, findingsBefore + 1);
    assert.equal(findings[0].finding_class, 'observed_availability_gap');
    assert.equal(findings[0].target_id, 'tgt_fw');
    assert.equal(findings[0].protection_validation.comparison_context.evaluation_id, comparison.json.id);

    const again = await request(baseUrl, 'POST', '/v1/firewall-comparisons', {
      headers: admin(), body: { baseline_id: baseline.json.id, post_test_run_ids: ['run_pv_post'] },
    });
    assert.equal(again.status, 200);
    assert.equal(again.json.replayed, true);
    assert.equal(getStore().findings.length, findingsBefore + 1, 'replay never duplicates findings');

    const read = await request(baseUrl, 'GET', `/v1/firewall-comparisons/${comparison.json.id}`, { headers: viewer() });
    assert.equal(read.status, 200);
    assert.deepEqual(read.json.post_test_run_ids, ['run_pv_post']);
    assert.equal(read.json.digest_verified, true);

    const report = await request(baseUrl, 'GET', '/v1/reports/protection-validation', { headers: viewer() });
    assert.equal(report.status, 200, JSON.stringify(report.json));
    assert.equal(report.json.passive, true);
    assert.equal(report.json.executes_checks, false);
    assert.equal(report.json.units.firewall_expectations.denominator, 1);
    assert.equal(report.json.units.firewall_expectations.gaps.required_service_newly_unavailable, 1);
    assert.equal(report.json.detection.counts_as_enforcement, false);
    const csv = await fetch(`${baseUrl}/v1/reports/protection-validation?format=csv`, { headers: viewer() });
    assert.equal(csv.status, 200);
    assert.match(csv.headers.get('content-type'), /text\/csv/);

    assert.equal(resolveDevProtectionRetestAuthorization({ tenantId: TENANT }, findings[0]).ok, true);
    const authorizedRetest = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: admin(),
      body: { check_id: 'tls.full_audit.safe', target_group_id: 'tg_1', target_id: 'tgt_fw', retest_of_finding_id: findings[0].id },
    });
    assert.ok(authorizedRetest.status < 300, JSON.stringify(authorizedRetest.json));
    const lineage = getStore().findingRetestLineage.find((row) => row.finding_id === findings[0].id);
    assert.equal(lineage.comparison_context.evaluation_id, comparison.json.id);
    assert.equal(lineage.comparison_context.comparison_kind, 'firewall_change');
    const retestRunId = authorizedRetest.json.run?.id ?? authorizedRetest.json.id;
    const retestRun = getStore().testRuns.find((row) => row.id === retestRunId);
    if (retestRun && ['planned', 'running', 'collecting'].includes(retestRun.status)) {
      const cancelled = await request(baseUrl, 'POST', `/v1/test-runs/${retestRunId}/cancel`, { headers: admin(), body: { reason: 'test' } });
      assert.ok(cancelled.status < 300, JSON.stringify(cancelled.json));
    }
    const archived = await request(baseUrl, 'POST', `/v1/firewall-expectations/${expectation.json.id}/archive`, { headers: admin() });
    assert.equal(archived.status, 200);
    const retest = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: admin(),
      body: { check_id: 'tls.full_audit.safe', target_group_id: 'tg_1', target_id: 'tgt_fw', retest_of_finding_id: findings[0].id },
    });
    assert.equal(retest.status, 409, JSON.stringify(retest.json));
    assert.equal(retest.json.error, 'retest_not_authorized');
    assert.equal(retest.json.reason, 'expectation_not_active');
  });

  it('requires current ownership of the baseline destination', async () => {
    addTarget({ id: 'tgt_fw_unowned', kind: 'fqdn', value: 'unowned.example.test' }, { verified: false });
    const expectation = await request(baseUrl, 'POST', '/v1/firewall-expectations', {
      headers: admin(),
      body: { destination_target_id: 'tgt_fw_unowned', protocol: 'tcp', port: 443, expected: 'allow', source_perspective: SOURCE, change_id: 'CHG-2002' },
    });
    assert.equal(expectation.status, 201, JSON.stringify(expectation.json));
    addTlsRun('run_pv_unowned', { target: 'tgt_fw_unowned', day: '2026-10-01' });
    const baseline = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: admin(), body: { change_id: 'CHG-2002', expectation_ids: [expectation.json.id], test_run_ids: ['run_pv_unowned'] },
    });
    assert.equal(baseline.status, 409, JSON.stringify(baseline.json));
    assert.equal(baseline.json.error, 'ownership_not_verified');
  });
});
