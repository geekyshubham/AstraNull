import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { computeTargetGroupScopeHash } from '../../src/lib/scopeHash.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { createServer } from '../../src/server.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import {
  createOffensiveRequest,
  planCanarySinkBody,
  recordCanarySinkBodyObservations,
} from '../../src/services/wafOffensive.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SECRET = 'f1a-dev-probe-worker-secret-at-least-32-chars!!';
const CTX = { tenantId: 'ten_demo', userId: 'usr_f1a', role: 'admin' };
const SOC = { tenantId: 'ten_demo', userId: 'usr_soc', role: 'soc' };
const DENY_22 = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };

function signedWorkerRuntime() {
  return loadRuntimeConfig({ NODE_ENV: 'test', ASTRANULL_NO_PERSIST: '1', ASTRANULL_PROBE_MODE: 'signed-worker', ASTRANULL_PROBE_WORKER_SECRET: SECRET });
}

function verify(targetId) {
  const store = getStore();
  store.targetVerifications ??= [];
  store.targetVerifications.push({
    id: `tv_${targetId}`, tenant_id: 'ten_demo', target_id: targetId, state: 'dns_verified', source_kind: 'dns_token',
    source_ref: {}, transitioned_at: new Date().toISOString(), transitioned_by: 'system',
  });
}

function seedReplayRun() {
  const store = getStore();
  const target = store.targets.find((row) => row.id === 'tgt_1');
  target.metadata = { ...(target.metadata ?? {}), control_declarations: DENY_22 };
  store.testRuns.push({
    id: 'run_f1a_replay', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'nfw.declared_deny_tcp.safe',
    status: 'verdicted', probe_external_result: 'connected', correlation: { nonce_hash: 'nh_f1a' }, created_at: new Date().toISOString(),
  });
  store.events.push({
    id: 'evt_f1a_replay', tenant_id: 'ten_demo', test_run_id: 'run_f1a_replay', target_id: 'tgt_1', check_id: 'nfw.declared_deny_tcp.safe',
    source: 'probe_worker', signal_type: 'probe_result', producer_kind: 'signed_probe', nonce_hash: 'nh_f1a', timestamp: new Date().toISOString(),
    metadata: { probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
      safety_attestation: { probe_requests_sent: 2 } },
  });
  store.verdicts.push({
    id: 'vrd_f1a_replay', tenant_id: 'ten_demo', test_run_id: 'run_f1a_replay', target_id: 'tgt_1', check_id: 'nfw.declared_deny_tcp.safe',
    verdict: 'inconclusive', confidence: 'external_only', explanation: 'recorded before the deny was declared', evidence_ids: ['evt_f1a_replay'],
  });
}

describe('F1a dev verdict replay route', () => {
  let server;
  let baseUrl;

  before(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    freshStore();
    seedReplayRun();
    const env = { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_NO_PERSIST: '1' };
    server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
    server.listen(0);
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await closeServer(server);
  });

  it('re-derives the stored run with current declarations and is tenant scoped', async () => {
    const replay = await request(baseUrl, 'GET', '/v1/test-runs/run_f1a_replay/verdict-replay', { headers: demoHeaders('viewer') });
    assert.equal(replay.status, 200, replay.text);
    assert.equal(replay.json.stored.verdict, 'inconclusive');
    assert.equal(replay.json.rederived.verdict, 'exposed');
    assert.equal(replay.json.rederived.declarations_applied, true);
    assert.equal(replay.json.changed, true);
    assert.equal(replay.json.grading_version_gap, null);
    assert.equal(getStore().verdicts.find((row) => row.id === 'vrd_f1a_replay').verdict, 'inconclusive');
    const foreign = await request(baseUrl, 'GET', '/v1/test-runs/run_f1a_replay/verdict-replay', { headers: demoHeaders('admin', 'ten_other', 'usr_other') });
    assert.equal(foreign.status, 404);
    const missing = await request(baseUrl, 'GET', '/v1/test-runs/run_missing/verdict-replay', { headers: demoHeaders('viewer') });
    assert.equal(missing.status, 404);
  });
});

describe('F1a dev origin lockdown on a hostname target', () => {
  it('signs the bound public origin IP with the target Host/SNI and refuses a private origin', () => {
    freshStore();
    const store = getStore();
    verify('tgt_1');
    store.targets.push({ id: 'tgt_origin_pub', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'ip', value: '8.8.8.8' });
    verify('tgt_origin_pub');
    store.originBindings = [{
      id: 'ob_dev', tenant_id: 'ten_demo', protected_target_id: 'tgt_1', protected_target_group_id: 'tg_1',
      origin_target_id: 'tgt_origin_pub', origin_target_group_id: 'tg_1', host: 'origin.test', sni: 'origin.test', port: null, path: null, status: 'active',
    }];
    const runtime = signedWorkerRuntime();
    const undeclared = startTestRun(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'nfw.origin_lockdown.safe' }, runtime);
    assert.equal(undeclared.error, 'declared_origin_lockdown_required');
    assert.equal(undeclared.status, 409);

    const target1 = store.targets.find((row) => row.id === 'tgt_1');
    target1.metadata = { ...(target1.metadata ?? {}), control_declarations: { version: 1, origin: { lockdown_expected: true } } };

    const started = startTestRun(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'nfw.origin_lockdown.safe' }, runtime);
    assert.equal(started.error, undefined, JSON.stringify(started));
    const job = store.probeJobs.find((row) => row.test_run_id === started.run.id);
    assert.equal(job.probe_profile.direct_ip, '8.8.8.8');
    assert.equal(job.probe_profile.protected_host, 'origin.test');
    assert.deepEqual(job.constraints.origin_scope, { host: 'origin.test', sni: 'origin.test', port: null, path: null });
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
    store.testRuns.find((row) => row.id === started.run.id).status = 'cancelled';

    store.targets.find((row) => row.id === 'tgt_origin_pub').value = '169.254.169.254';
    const refused = startTestRun(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'nfw.origin_lockdown.safe' }, runtime);
    assert.equal(refused.error, 'origin_destination_not_allowed');
    store.originBindings = [];
    const unbound = startTestRun(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'nfw.origin_lockdown.safe' }, runtime);
    assert.equal(unbound.error, 'missing_declared_origin_binding');
  });
});

describe('F1a dev canary-sink binding', () => {
  function approvedRequest() {
    freshStore();
    const store = getStore();
    store.wafAssets = [{ id: 'waf_dev', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', canonical_url: 'https://origin.test' }];
    const created = createOffensiveRequest(SOC, {
      waf_asset_id: 'waf_dev', objective: 'Canary sink', requested_suites: ['sqli_offensive'],
      emergency_contacts: ['ops@example.invalid'], scope_confirmation: true, staging_only: true,
    });
    const record = store.wafOffensiveRequests.find((row) => row.id === created.offensive_request.id);
    record.state = 'approved';
    record.scope_hash = computeTargetGroupScopeHash('ten_demo', 'tg_1');
    return record;
  }

  function declareSink(url) {
    const target = getStore().targets.find((row) => row.id === 'tgt_1');
    target.metadata = { ...(target.metadata ?? {}), control_declarations: { version: 1, canary_sink: { url } } };
  }

  function refusals(requestId) {
    return getStore().auditLog
      .filter((row) => row.action === 'waf.offensive_canary_sink_body.refused' && row.resource_id === requestId)
      .map((row) => row.metadata.reason);
  }

  it('refuses an undeclared sink, an out-of-scope target, a changed scope and a changed declaration, and audits each refusal', () => {
    const record = approvedRequest();
    assert.equal(planCanarySinkBody(SOC, record.id, { variants: ['json'] }).error, 'canary_sink_not_declared');
    declareSink('https://origin.test/canary');
    assert.equal(planCanarySinkBody(SOC, record.id, { target_id: 'tgt_other', variants: ['json'] }).error, 'canary_sink_target_out_of_scope');
    const planned = planCanarySinkBody(SOC, record.id, { declared_canary_sink_url: 'https://evil.example.invalid/x', variants: ['json'] });
    assert.equal(planned.plan.canary_sink_url, 'https://origin.test/canary');
    declareSink('https://origin.test/other-sink');
    const changed = recordCanarySinkBodyObservations(SOC, record.id, { observations: [{ id: 'json_marker', blocked: true }] });
    assert.equal(changed.error, 'canary_sink_declaration_changed');
    declareSink('https://origin.test/canary');
    getStore().targets.push({ id: 'tgt_late', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'late.origin.test' });
    assert.equal(planCanarySinkBody(SOC, record.id, { variants: ['json'] }).error, 'scope_hash_mismatch');
    assert.deepEqual(refusals(record.id), [
      'canary_sink_not_declared', 'canary_sink_target_out_of_scope', 'canary_sink_declaration_changed', 'scope_hash_mismatch',
    ]);
    assert.ok(getStore().auditLog.some((row) => row.action === 'waf.offensive_canary_sink_body.planned' && row.resource_id === record.id));
    assert.equal((getStore().probeJobs ?? []).length, 0);
  });

  it('records observations only for the stored plan once the request is approved', () => {
    const record = approvedRequest();
    declareSink('https://origin.test/canary');
    assert.equal(recordCanarySinkBodyObservations(SOC, record.id, { observations: [] }).error, 'canary_sink_plan_missing');
    assert.ok(planCanarySinkBody(SOC, record.id, { variants: ['json'] }).plan);
    record.state = 'rejected';
    assert.equal(recordCanarySinkBodyObservations(SOC, record.id, { observations: [] }).error, 'canary_sink_request_not_approved');
    record.state = 'running';
    const observed = recordCanarySinkBodyObservations(SOC, record.id, { observations: [{ id: 'json_marker', blocked: true, status_code: 403 }] });
    assert.equal(observed.results.variant_results[0].outcome, 'blocked');
  });
});
