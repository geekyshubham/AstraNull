import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { additionalInputRefusal, getCheckById, WAF_SAFE_CHECK_IDS } from '../../src/contracts/checks.mjs';
import { SCENARIO_TO_CHECK } from '../../src/contracts/wafOrchestrator.mjs';
import { firewallSideState } from '../../src/contracts/protectionValidation.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { versionGapFor } from '../../src/lib/protectionCoverage.mjs';
import { probeReflectionService } from '../../src/lib/safeNetworkProbes.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { recordEvidence } from '../../src/services/evidence.mjs';
import { applyPassingRetestToFindings, upsertFindingFromVerdict } from '../../src/services/findings.mjs';
import { planCanarySinkBody, recordCanarySinkBodyObservations, createOffensiveRequest } from '../../src/services/wafOffensive.mjs';
import { getStore } from '../../src/store.mjs';
import { computeTargetGroupScopeHash } from '../../src/lib/scopeHash.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { EventEmitter } from 'node:events';

const PUBLIC_IP = '8.8.8.8';
const CTX = { tenantId: 'ten_demo', userId: 'usr_soc', role: 'soc' };

function recordingSockets({ reply = null, sendError = null } = {}) {
  const sends = [];
  const createSocket = (type) => {
    const socket = new EventEmitter();
    socket.type = type;
    socket.bind = () => {};
    socket.send = (payload, port, host, cb) => {
      sends.push({ bytes: payload.length, port, host });
      if (sendError) {
        cb?.(sendError);
        return;
      }
      cb?.(null);
      if (reply) {
        setImmediate(() => socket.emit('message', reply, { address: host, port, family: 'IPv4', size: reply.length }));
      }
    };
    socket.close = () => {};
    return socket;
  };
  return { createSocket, sends };
}

function reflectionJob(overrides = {}) {
  return {
    nonce_hash: 'r1',
    target: { value: `${PUBLIC_IP}:1900` },
    probe_profile: { kind: 'reflection_service_probe', payload_profile: 'ssdp_msearch' },
    constraints: { timeout_ms: 60, max_requests: 1 },
    ...overrides,
  };
}

describe('R1 reconcile: UDP outcomes, wiring, SOC canary-sink', () => {
  it('maps a closed UDP port to timeout and keeps icmp/udp_outcome metadata', async () => {
    const err = Object.assign(new Error('port unreachable'), { code: 'ECONNREFUSED' });
    const result = await probeReflectionService(reflectionJob(), recordingSockets({ sendError: err }));
    assert.equal(result.external_result, 'timeout');
    assert.equal(result.metadata.udp_outcome, 'port_unreachable');
    assert.notEqual(result.external_result, 'blocked');
    assert.ok(result.metadata.icmp == null || typeof result.metadata.icmp === 'object');
  });

  it('maps an unvalidated same-size reply to not_run and never confirms a reflector', async () => {
    const junk = recordingSockets({ reply: Buffer.alloc(200, 0x41) });
    const result = await probeReflectionService(reflectionJob({
      probe_profile: { kind: 'reflection_service_probe', payload_profile: 'memcached_udp_stats' },
      target: { value: `${PUBLIC_IP}:11211` },
    }), junk);
    assert.equal(result.external_result, 'not_run');
    assert.equal(result.metadata.udp_outcome, 'unvalidated_reply');
    assert.equal(result.metadata.reflector_confirmed, false);
  });

  it('treats a recorded grading or corpus mismatch as a version gap and ignores unstamped NFW', () => {
    const check = getCheckById('waf.marker_rule.safe');
    const current = deriveCheckDefinitionVersion(check);
    const scenario = approvedScenarioVersion(check);
    const stamped = {
      check_version: current.check_version,
      ...(scenario ? { scenario_version: scenario } : {}),
    };
    assert.equal(versionGapFor(check, stamped, {}), null);
    assert.equal(versionGapFor(check, { ...stamped, grading_version: 'waf-grading.v1' }, {}), 'grading_version_mismatch');
    assert.equal(versionGapFor(check, {
      ...stamped,
      grading_version: WAF_GRADING_VERSION,
      signature_corpus_version: 'old-corpus',
    }, {}), 'signature_corpus_version_mismatch');
    const nfw = getCheckById('nfw.declared_deny_tcp.safe');
    const nfwCurrent = deriveCheckDefinitionVersion(nfw);
    const nfwScenario = approvedScenarioVersion(nfw);
    assert.equal(versionGapFor(nfw, {
      check_version: nfwCurrent.check_version,
      ...(nfwScenario ? { scenario_version: nfwScenario } : {}),
    }, {}), null);
  });

  it('closes matching open findings from a complete passing retest and audits finding.fix_verified', () => {
    freshStore();
    const target = getStore().targets[0];
    const run = {
      id: 'run_origin',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: target.id,
      check_id: 'origin.direct_bypass.safe',
      status: 'verdicted',
      check_version: '1.0.0',
      grading_version: WAF_GRADING_VERSION,
    };
    const exposed = {
      id: 'vd_origin',
      tenant_id: 'ten_demo',
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      verdict: 'exposed',
      severity: 'high',
      explanation: 'Origin answered directly.',
      evidence_ids: ['ev_1'],
      grading_version: WAF_GRADING_VERSION,
    };
    getStore().testRuns.push(run);
    const finding = upsertFindingFromVerdict(CTX, exposed, run, target);
    const applied = applyPassingRetestToFindings(CTX, {
      verdict: {
        id: 'vd_pass',
        verdict: 'protected',
        check_id: run.check_id,
        target_id: run.target_id,
        grading_version: WAF_GRADING_VERSION,
        metadata: { complete: true, comparison_complete: true },
      },
      run: { ...run, id: 'run_retest' },
      target,
    });
    assert.deepEqual(applied.closed, [finding.id]);
    assert.equal(getStore().findings[0].status, 'fix_verified');
    assert.equal(getStore().auditLog.find((row) => row.action === 'finding.fix_verified').resource_id, finding.id);
    const testRunsSrc = readFileSync(fileURLToPath(new URL('../../src/services/testRuns.mjs', import.meta.url)), 'utf8');
    assert.match(testRunsSrc, /applyPassingRetestToFindings/);
    const pgSrc = readFileSync(fileURLToPath(new URL('../../src/persistence/postgres/validationServiceAdapters.mjs', import.meta.url)), 'utf8');
    assert.match(pgSrc, /planFixVerifiedFromRetest/);
    assert.match(pgSrc, /finding\.fix_verified/);
  });

  it('persists redacted response_features onto evidence records', () => {
    freshStore();
    const recorded = recordEvidence(CTX, {
      test_run_id: 'run_1',
      metadata: {
        probe_kind: 'waf_class_marker_probe',
        external_result: 'blocked',
        response_features: [{
          placement: 'path',
          status_code: 403,
          header_subset: { server: 'cloudflare', authorization: 'secret' },
          body_length_bucket: '0-64',
          signature_id: 'sig_1',
        }],
      },
    });
    assert.equal(recorded.response_features[0].placement, 'path');
    assert.notEqual(JSON.stringify(recorded).includes('secret'), true);
    const coordinatorSrc = readFileSync(fileURLToPath(new URL('../../src/services/probeCoordinator.mjs', import.meta.url)), 'utf8');
    assert.match(coordinatorSrc, /response_features: workerMetadata\.response_features/);
    const pgSrc = readFileSync(fileURLToPath(new URL('../../src/persistence/postgres/probeJobServiceAdapters.mjs', import.meta.url)), 'utf8');
    assert.match(pgSrc, /response_features: responseFeatures/);
  });

  it('keeps managed marker checks on WAF_SAFE_CHECK_IDS and maps orchestrator scenarios away from marker_rule', () => {
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.sqli_managed_marker.safe'));
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.xss_managed_marker.safe'));
    assert.ok(WAF_SAFE_CHECK_IDS.includes('waf.path_traversal_managed_marker.safe'));
    assert.equal(SCENARIO_TO_CHECK.sqli_marker, 'waf.sqli_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.xss_marker, 'waf.xss_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.path_traversal_marker, 'waf.path_traversal_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.rce_marker, 'waf.offensive_rce.soc');
    assert.notEqual(SCENARIO_TO_CHECK.sqli_marker, 'waf.marker_rule.safe');
    const orchSrc = readFileSync(fileURLToPath(new URL('../../src/services/wafOrchestrator.mjs', import.meta.url)), 'utf8');
    assert.equal(orchSrc.includes('MANAGED_MARKER_ORCHESTRATOR_CHECK_IDS'), false);
  });

  it('correlates method-policy enforcement and a denied-perspective handshake', () => {
    const enforced = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'enforced', comparison_complete: true },
    });
    assert.equal(enforced.verdict, 'protected');
    const exposed = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'not_enforced', comparison_complete: true },
    });
    assert.equal(exposed.verdict, 'exposed');
    assert.equal(exposed.severity, 'low');
    const two = {
      ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
        { id: 'eu', label: 'EU', egress_ips: [] },
        { id: 'us', label: 'US', egress_ips: [] },
      ]),
    };
    const allowlist = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      checkId: 'nfw.perspective_allowlist.safe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: { tcp_outcome: 'handshake', source_perspective: { id: 'eu' }, claimed_perspective_id: 'eu', perspective_authenticated: true },
      declarations: { perspectives: { denied_perspective_ids: ['eu'] } },
      env: two,
    });
    assert.equal(allowlist.verdict, 'exposed');
    assert.equal(allowlist.severity, 'medium');
    const check = getCheckById('nfw.perspective_allowlist.safe');
    assert.equal(additionalInputRefusal(check, {}).error, 'two_perspectives_required');
    assert.equal(additionalInputRefusal(check, two).error, 'declared_perspectives_required');
    assert.equal(additionalInputRefusal(check, two, { declarations: { perspectives: { denied_perspective_ids: ['eu'] } } }), null);
  });

  it('sends up to four composite reflection profiles and never exceeds four', async () => {
    const sockets = recordingSockets();
    const result = await probeReflectionService({
      nonce_hash: 'composite',
      check_id: 'reflect.dtls_sip_rdp_tftp_exposure.safe',
      target: { value: `${PUBLIC_IP}:443` },
      probe_profile: {
        kind: 'reflection_service_probe',
        payload_profile: 'dtls_sip_rdp_tftp',
        max_requests: 4,
      },
      constraints: { timeout_ms: 200 },
    }, sockets);
    assert.ok(sockets.sends.length <= 4, `sent ${sockets.sends.length}`);
    assert.ok(result.requests_sent <= 4);
    assert.equal(result.metadata.payload_profiles_declared.length, 4);
    const ssdp = recordingSockets();
    const single = await probeReflectionService(reflectionJob({ constraints: { timeout_ms: 60, max_requests: 1000 } }), ssdp);
    assert.ok(ssdp.sends.length <= 2);
    assert.ok(single.requests_sent <= 2);
  });

  it('does not satisfy a deny expectation from a single explicit-denial sample', () => {
    assert.equal(firewallSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 1,
      classes: ['explicit_denial_observed'],
    }), 'unverified');
    assert.equal(firewallSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 2,
      classes: ['explicit_denial_observed'],
    }), 'satisfied');
  });

  it('plans a canary-sink body suite and records SOC observations without a probe job', () => {
    freshStore();
    getStore().wafAssets = [{
      id: 'waf_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      canonical_url: 'https://waf-offensive.example.com',
    }];
    const created = createOffensiveRequest(CTX, {
      waf_asset_id: 'waf_1',
      objective: 'Plan a canary-sink body suite',
      requested_suites: ['sqli_offensive'],
      emergency_contacts: ['ops@example.invalid'],
      scope_confirmation: true,
      staging_only: true,
    });
    const requestId = created.offensive_request.id;
    const stored = getStore().wafOffensiveRequests.find((row) => row.id === requestId);
    stored.state = 'approved';
    stored.scope_hash = computeTargetGroupScopeHash('ten_demo', 'tg_1');
    const target = getStore().targets.find((row) => row.id === 'tgt_1');
    target.metadata = { ...(target.metadata ?? {}), control_declarations: { version: 1, canary_sink: { url: 'https://origin.test/canary' } } };
    const jobsBefore = (getStore().probeJobs ?? []).length;
    const planned = planCanarySinkBody(CTX, requestId, {
      canary_sink_url: 'https://origin.test/canary',
      variants: ['json'],
    });
    assert.ok(planned.plan);
    assert.equal(planned.plan.requests.length, 1);
    assert.equal((getStore().probeJobs ?? []).length, jobsBefore);
    const observed = recordCanarySinkBodyObservations(CTX, requestId, {
      observations: [{ id: 'json_marker', blocked: true, status_code: 403 }],
    });
    assert.equal(observed.results.variant_results[0].outcome, 'blocked');
    assert.equal((getStore().probeJobs ?? []).length, jobsBefore);
    assert.equal(getStore().wafOffensiveRequests[0].canary_sink_body_plan.requests.length, 1);
    assert.ok(getStore().auditLog.some((row) => row.action === 'waf.offensive_canary_sink_body.planned'));
    assert.ok(getStore().auditLog.some((row) => row.action === 'waf.offensive_canary_sink_body.observed'));
  });
});
