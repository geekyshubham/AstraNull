import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  buildSignedProbeJobRecord,
  jobClaimableByPerspective,
  OriginLockdownBindingMissingError,
  originLockdownProvenance,
  requiredPerspectiveIdForJob,
  resolveOriginLockdownBinding as resolveWithHelpers,
  validateHostSniTargetBinding,
  verifyProbeJobSignature,
} from '../../src/lib/probeJobs.mjs';
import { buildVerdictReplay } from '../../src/lib/verdictReplay.mjs';
import { WAF_GRADING_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import {
  authenticateProbeWorker,
  createProbeJob,
  ingestProbeResult,
  listPendingProbeJobsForWorker,
  probeWorkerAuthHeaders,
  reserveProbeExecution,
} from '../../src/services/probeCoordinator.mjs';
import { currentOriginProof, deriveBindingScope } from '../../src/services/originBindings.mjs';

const resolveOriginLockdownBinding = (input) => resolveWithHelpers({ ...input, deriveBindingScope, currentOriginProof });
import { getStore } from '../../src/store.mjs';
import { finalizeTestRun } from '../../src/services/testRuns.mjs';
import { parseWorkerConfig, sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SECRET = 'f1a-probe-worker-secret-at-least-32-chars!!';
const NOW = new Date();
const DENY_22 = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };

function run(extra = {}) {
  return { id: 'run_f1a', tenant_id: 'ten_demo', created_at: NOW.toISOString(), safety_constraints: {}, ...extra };
}

function fqdnTarget(metadata = undefined) {
  return { id: 'tgt_f1a', kind: 'fqdn', value: 'app.f1a.example.com', ...(metadata ? { metadata } : {}) };
}

function build(check, target, runExtra = {}, extra = {}) {
  return buildSignedProbeJobRecord({
    run: run(runExtra), check, target, probeWorkerSecret: SECRET, now: NOW, newId: () => 'pjob_f1a', ...extra,
  });
}

describe('D1 shared job builder attaches signed declarations', () => {
  it('copies a declared deny tcp/22 into the signed probe profile from target metadata', () => {
    const job = build(getCheckById('nfw.declared_deny_tcp.safe'), fqdnTarget({ control_declarations: DENY_22 }));
    assert.deepEqual(job.probe_profile.declarations.network_policy, DENY_22.network_policy);
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
    const tampered = structuredClone(job);
    tampered.probe_profile.declarations.network_policy[0].action = 'allow';
    assert.equal(verifyProbeJobSignature(tampered, SECRET), false);
  });

  it('accepts explicitly loaded declarations and leaves undeclared targets unchanged', () => {
    const check = getCheckById('nfw.declared_deny_tcp.safe');
    const explicit = build(check, fqdnTarget(), {}, { declarations: DENY_22 });
    assert.equal(explicit.probe_profile.declarations.network_policy[0].port, 22);
    const plain = build(check, fqdnTarget());
    assert.equal(plain.probe_profile.declarations, undefined);
  });

  it('dev createProbeJob uses the same builder output', () => {
    freshStore();
    const job = createProbeJob({ tenantId: 'ten_demo', userId: 'u1', role: 'engineer' }, run(),
      getCheckById('nfw.declared_deny_tcp.safe'), fqdnTarget({ control_declarations: DENY_22 }), undefined, { probeWorkerSecret: SECRET });
    assert.deepEqual(job.probe_profile.declarations.network_policy, DENY_22.network_policy);
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
  });
});

describe('D4 worker metadata sanitizer', () => {
  const fullShape = {
    probe_kind: 'waf_class_marker_probe',
    placements: [{ placement: 'query', outcome: 'blocked', status_code: 403, signature_id: 'cloudflare', cache_status: null, location_changed: false }],
    trailing_control: { outcome: 'allowed', status_code: 200 },
    response_features: [{ placement: 'query', status_code: 403, header_subset: { server: 'cloudflare', 'set-cookie': 'secret' }, body_length_bucket: 'lt_4kb', signature_id: 'cloudflare' }],
    paths: [{ path: '/', posture: 'protected', posture_status: 'blocked_all', enforcement: 'enforced', source_penalized: false,
      placements: [{ placement: 'header', outcome: 'blocked', status_code: 403 }], trailing_control: { outcome: 'allowed', status_code: 200 } }],
    leg_order: ['query', 'header', 'path'],
    method_results: [{ method: 'TRACE', outcome: 'blocked', status_code: 405, signature_id: null, reason: null, origin_rejected: false }],
    families: {
      ipv4: { tcp_outcome: 'handshake', port: 22, address: '198.51.100.7', peer_is_cdn: false, sample_agreement: 'agree',
        samples: [{ tcp_outcome: 'handshake', icmp: null }], open_ports: [22] },
      ipv6: { tcp_outcome: 'refused_rst', icmp: { kind: 'port_unreachable', errno: 'ECONNREFUSED' } },
    },
    parity: 'mismatch',
    sample_agreement: 'agree',
    source_perspective: { id: 'eu-1', label: 'EU 1' },
    requests_sent: 3,
    first_limited_at: 4,
    accepted_count: 5,
    declared_limit: 4,
  };

  it('keeps a full new-shape metadata document', () => {
    const out = sanitizeProbeMetadata(fullShape);
    assert.deepEqual(out.placements, fullShape.placements);
    assert.deepEqual(out.trailing_control, fullShape.trailing_control);
    assert.deepEqual(out.response_features[0].header_subset, { server: 'cloudflare' });
    assert.equal(out.paths[0].placements[0].outcome, 'blocked');
    assert.deepEqual(out.leg_order, fullShape.leg_order);
    assert.deepEqual(out.method_results, fullShape.method_results);
    assert.deepEqual(out.families.ipv4.open_ports, [22]);
    assert.equal(out.families.ipv4.samples[0].tcp_outcome, 'handshake');
    assert.deepEqual(out.families.ipv6.icmp, { kind: 'port_unreachable', errno: 'ECONNREFUSED' });
    assert.deepEqual(out.source_perspective, { id: 'eu-1', label: 'EU 1' });
    for (const key of ['parity', 'sample_agreement', 'requests_sent', 'first_limited_at', 'accepted_count', 'declared_limit']) {
      assert.equal(out[key], fullShape[key], key);
    }
  });

  it('truncates oversized arrays and long strings', () => {
    const out = sanitizeProbeMetadata({
      leg_order: Array.from({ length: 50 }, (_, index) => `leg_${index}`),
      placements: Array.from({ length: 40 }, () => ({ placement: 'q'.repeat(400), outcome: 'blocked' })),
    });
    assert.equal(out.leg_order.length, 32);
    assert.equal(out.placements.length, 32);
    assert.equal(out.placements[0].placement.length, 256);
  });

  it('still drops unknown and denied keys', () => {
    const out = sanitizeProbeMetadata({
      placements: [{ placement: 'query', outcome: 'blocked', raw_body: 'x', nested: { a: 1 } }],
      families: { ipv4: { tcp_outcome: 'handshake', banner: { text: 'ssh' } }, ipv9: { tcp_outcome: 'handshake' } },
      source_perspective: { id: 'eu-1', label: 'EU', secret: 'x' },
      unknown_list: [1, 2, 3],
      headers: { authorization: 'Bearer x' },
      body: 'payload',
    });
    assert.deepEqual(out.placements, [{ placement: 'query', outcome: 'blocked' }]);
    assert.deepEqual(out.families, { ipv4: { tcp_outcome: 'handshake' } });
    assert.deepEqual(out.source_perspective, { id: 'eu-1', label: 'EU' });
    assert.equal('unknown_list' in out, false);
    assert.equal('headers' in out, false);
    assert.equal('body' in out, false);
  });
});

describe('F12 perspective routing', () => {
  const perspectiveCheck = getCheckById('nfw.perspective_allowlist.safe');
  const declarations = { version: 1, perspectives: { allowlisted_perspective_ids: ['us-1'], denied_perspective_ids: ['eu-1'] } };

  it('pins perspective allowlist jobs to the first denied perspective and signs it', () => {
    assert.equal(requiredPerspectiveIdForJob(perspectiveCheck, declarations), 'eu-1');
    assert.equal(requiredPerspectiveIdForJob(perspectiveCheck, { perspectives: { allowlisted_perspective_ids: ['us-1'] } }), 'us-1');
    assert.equal(requiredPerspectiveIdForJob(getCheckById('nfw.declared_deny_tcp.safe'), declarations), null);
    const job = build(perspectiveCheck, fqdnTarget({ control_declarations: declarations }));
    assert.equal(job.constraints.required_perspective_id, 'eu-1');
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
    assert.equal(jobClaimableByPerspective(job, 'eu-1'), true);
    assert.equal(jobClaimableByPerspective(job, 'us-1'), false);
    assert.equal(jobClaimableByPerspective(job, null), false);
    assert.equal(jobClaimableByPerspective({ constraints: {} }, null), true);
  });

  it('dev lease, reserve and ingest honor the required perspective', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({ id: 'run_f1a', tenant_id: 'ten_demo', status: 'running', target_id: 'tgt_1', check_id: perspectiveCheck.check_id, correlation: {} });
    store.testRuns.push({ id: 'run_f1a_open', tenant_id: 'ten_demo', status: 'running', target_id: 'tgt_1', check_id: 'nfw.declared_deny_tcp.safe', correlation: {} });
    const pinned = build(perspectiveCheck, fqdnTarget({ control_declarations: declarations }));
    const open = { ...build(getCheckById('nfw.declared_deny_tcp.safe'), fqdnTarget()), id: 'pjob_open', test_run_id: 'run_f1a_open' };
    store.probeJobs.push(pinned, open);
    const other = listPendingProbeJobsForWorker({ tenantId: 'ten_demo', workerId: 'w_us', perspectiveId: 'us-1' });
    assert.deepEqual(other.map((job) => job.id), ['pjob_open']);
    assert.equal(reserveProbeExecution({ tenantId: 'ten_demo', workerId: 'w_us', perspectiveId: 'us-1' }, pinned.id, { leased_at: 'x' }).error, 'probe_perspective_mismatch');
    assert.equal(ingestProbeResult({ tenantId: 'ten_demo', workerId: 'w_us', perspectiveId: 'us-1' }, pinned.id, {}, {}).error, 'probe_perspective_mismatch');
    const matching = listPendingProbeJobsForWorker({ tenantId: 'ten_demo', workerId: 'w_eu', perspectiveId: 'eu-1' });
    assert.deepEqual(matching.map((job) => job.id), [pinned.id]);
  });

  it('covers the worker perspective header with the HMAC and the worker reads its env id', () => {
    const runtime = { probeMode: 'signed-worker', probeWorkerSecret: SECRET };
    const headers = probeWorkerAuthHeaders('w_eu', { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_demo', perspectiveId: 'eu-1' }, SECRET);
    const ok = authenticateProbeWorker(headers, 'GET', '/internal/probe/jobs', '', runtime);
    assert.equal(ok.ok, true);
    assert.equal(ok.workerCtx.perspectiveId, 'eu-1');
    assert.equal(authenticateProbeWorker({ ...headers, 'x-probe-perspective-id': 'us-1' }, 'GET', '/internal/probe/jobs', '', runtime).status, 401);
    const legacy = probeWorkerAuthHeaders('w_any', { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_demo' }, SECRET);
    assert.equal(authenticateProbeWorker(legacy, 'GET', '/internal/probe/jobs', '', runtime).workerCtx.perspectiveId, null);
    const env = { ASTRANULL_PROBE_WORKER_SECRET: randomBytes(32).toString('hex'), ASTRANULL_PROBE_TENANT_ID: 'ten_demo' };
    assert.equal(parseWorkerConfig([], { ...env, ASTRANULL_PROBE_PERSPECTIVE_ID: 'eu-1' }).perspectiveId, 'eu-1');
    assert.throws(() => parseWorkerConfig([], { ...env, ASTRANULL_PROBE_PERSPECTIVE_ID: 'EU 1' }), /ASTRANULL_PROBE_PERSPECTIVE_ID/);
  });
});

describe('F13 origin lockdown on a hostname target', () => {
  const lockdown = getCheckById('nfw.origin_lockdown.safe');
  const protectedTarget = {
    id: 'tgt_app', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'app.f1a.example.com',
    metadata: { control_declarations: { version: 1, origin: { lockdown_expected: true } } },
  };
  const verification = (targetId) => ({ id: `tv_${targetId}`, tenant_id: 'ten_demo', target_id: targetId, state: 'dns_verified', transitioned_at: NOW.toISOString() });
  const records = (originValue) => ({
    targets: [protectedTarget, { id: 'tgt_origin', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'ip', value: originValue }],
    targetVerifications: [verification('tgt_app'), verification('tgt_origin')],
  });
  const binding = { id: 'ob_1', tenant_id: 'ten_demo', status: 'active', protected_target_id: 'tgt_app', origin_target_id: 'tgt_origin',
    host: 'app.f1a.example.com', sni: 'app.f1a.example.com', port: null, path: null };

  it('resolves the declared public origin IP and signs Host/SNI scope', () => {
    const resolved = resolveOriginLockdownBinding({ check: lockdown, target: protectedTarget, tenantId: 'ten_demo', bindings: [binding], records: records('8.8.8.8') });
    assert.equal(resolved.ok, true, JSON.stringify(resolved));
    assert.equal(validateHostSniTargetBinding(lockdown, protectedTarget, { originLockdown: resolved }), null);
    const job = build(lockdown, protectedTarget, { provenance_json: { origin_lockdown: originLockdownProvenance(resolved) } });
    assert.equal(job.probe_profile.direct_ip, '8.8.8.8');
    assert.equal(job.probe_profile.protected_host, 'app.f1a.example.com');
    assert.deepEqual(job.constraints.origin_scope, { host: 'app.f1a.example.com', sni: 'app.f1a.example.com', port: null, path: null });
    assert.equal(job.target.value, 'app.f1a.example.com');
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
  });

  it('refuses private, loopback, link-local and metadata origin addresses', () => {
    for (const address of ['10.0.0.5', '127.0.0.1', '169.254.169.254', '192.168.1.10', '::1']) {
      const resolved = resolveOriginLockdownBinding({ check: lockdown, target: protectedTarget, tenantId: 'ten_demo', bindings: [binding], records: records(address) });
      assert.equal(resolved.error, 'origin_destination_not_allowed', address);
      assert.equal(validateHostSniTargetBinding(lockdown, protectedTarget, { originLockdown: resolved }).error, 'origin_destination_not_allowed');
    }
  });

  it('refuses a missing, ambiguous or unverified binding and never builds without stored provenance', () => {
    assert.equal(validateHostSniTargetBinding(lockdown, protectedTarget).error, 'missing_declared_origin_binding');
    const none = resolveOriginLockdownBinding({ check: lockdown, target: protectedTarget, tenantId: 'ten_demo', bindings: [], records: records('8.8.8.8') });
    assert.equal(none.error, 'missing_declared_origin_binding');
    const two = resolveOriginLockdownBinding({ check: lockdown, target: protectedTarget, tenantId: 'ten_demo',
      bindings: [binding, { ...binding, id: 'ob_2' }], records: records('8.8.8.8') });
    assert.equal(two.error, 'origin_binding_ambiguous');
    const unverified = records('8.8.8.8');
    unverified.targetVerifications = [verification('tgt_app')];
    assert.equal(resolveOriginLockdownBinding({ check: lockdown, target: protectedTarget, tenantId: 'ten_demo', bindings: [binding], records: unverified }).error, 'ownership_not_verified');
    assert.throws(() => build(lockdown, protectedTarget), OriginLockdownBindingMissingError);
    const forged = { origin_lockdown: { binding_id: 'ob_1', address: '10.0.0.5', host: 'app.f1a.example.com', sni: 'app.f1a.example.com' } };
    assert.throws(() => build(lockdown, protectedTarget, { provenance_json: forged }), OriginLockdownBindingMissingError);
    assert.equal(resolveOriginLockdownBinding({ check: getCheckById('origin.host_sni_bypass.safe'), target: protectedTarget, tenantId: 'ten_demo' }), null);
  });
});

describe('F23 verdict replay projection', () => {
  const runRecord = { id: 'run_replay', tenant_id: 'ten_demo', check_id: 'nfw.declared_deny_tcp.safe', probe_external_result: 'connected' };
  const probeEvent = {
    metadata: { probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
      safety_attestation: { probe_requests_sent: 2 } },
  };

  it('re-derives with current declarations and reports a change', () => {
    const withDeny = buildVerdictReplay({ run: runRecord, storedVerdict: { verdict: 'inconclusive' }, probeEvent, declarations: DENY_22 });
    const withoutDeny = buildVerdictReplay({ run: runRecord, storedVerdict: { verdict: withDeny.rederived.verdict }, probeEvent, declarations: null });
    assert.equal(withDeny.rederived.declarations_applied, true);
    assert.equal(withoutDeny.rederived.declarations_applied, false);
    assert.equal(withDeny.rederived.verdict, 'exposed');
    assert.equal(withDeny.changed, true);
    assert.equal(withoutDeny.rederived.verdict, 'inconclusive');
    assert.equal(withoutDeny.changed, true);
    assert.equal(withDeny.grading_version_gap, null);
    assert.equal(buildVerdictReplay({ run: runRecord, probeEvent }).changed, null);
  });

  it('flags a grading version gap for graded WAF evidence', () => {
    const graded = buildVerdictReplay({ run: { ...runRecord, check_id: 'waf.marker_rule.safe' },
      storedVerdict: { verdict: 'protected', grading_version: 'waf-grading.v1' }, probeEvent: { metadata: { grading_version: 'waf-grading.v1' } } });
    assert.equal(graded.grading_version_gap, 'grading_version_mismatch');
    assert.equal(graded.rederived.grading_version, WAF_GRADING_VERSION);
  });
});

describe('F1a lead follow-ups', () => {
  it('keeps the bounded F1b metadata fields through the worker sanitizer', () => {
    const out = sanitizeProbeMetadata({
      requests_sent: 3,
      allowed_before_limit: 2,
      matched_vendor: 'cloudflare',
      inconclusive_reason: 'r'.repeat(400),
      ports_sampled: Array.from({ length: 40 }, (_, index) => index + 1),
      not_sampled: true,
      parity_ports: [22, 443],
      parity_reason: 'no_shared_ports_sampled',
      unqueried_nameservers: ['ns3.example.com'],
      local_error: true,
      local_error_ports: [25],
      placements: [{ placement: 'query', outcome: 'inconclusive', inconclusive_reason: 'block_suspected_unverified_signature', matched_vendor: 'akamai' }],
      families: { ipv6: { ports_sampled: [22], not_sampled: false, local_error_ports: [25], local_error: true, extra: { x: 1 } } },
    });
    assert.equal(out.requests_sent, 3);
    assert.equal(out.allowed_before_limit, 2);
    assert.equal(out.matched_vendor, 'cloudflare');
    assert.equal(out.inconclusive_reason.length, 256);
    assert.equal(out.ports_sampled.length, 32);
    assert.equal(out.not_sampled, true);
    assert.deepEqual(out.parity_ports, [22, 443]);
    assert.equal(out.parity_reason, 'no_shared_ports_sampled');
    assert.deepEqual(out.unqueried_nameservers, ['ns3.example.com']);
    assert.equal(out.local_error, true);
    assert.deepEqual(out.local_error_ports, [25]);
    assert.equal(out.placements[0].matched_vendor, 'akamai');
    assert.deepEqual(out.families.ipv6, { ports_sampled: [22], not_sampled: false, local_error_ports: [25], local_error: true });
  });

  it('passes the target to additionalInputRefusal so l3.basic_deny_rule.safe runs with a port or declared tcp deny', () => {
    const check = getCheckById('l3.basic_deny_rule.safe');
    assert.equal(validateHostSniTargetBinding(check, { id: 't1', kind: 'tcp', value: 'app.f1a.example.com:22' }), null);
    assert.equal(validateHostSniTargetBinding(check, fqdnTarget()).error, 'port_or_declared_deny_required');
    assert.equal(validateHostSniTargetBinding(check, fqdnTarget({ control_declarations: DENY_22 })), null);
  });

  it('persists the correlation exposure_basis on dev verdicts', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({
      id: 'run_f1a_reflect', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'reflect.ssdp_exposure.safe',
      status: 'collecting', probe_external_result: 'connected', correlation: { nonce_hash: 'nh_reflect' },
      collection_deadline_at: '2025-01-01T00:00:00.000Z', created_at: NOW.toISOString(),
    });
    store.events.push({
      id: 'evt_f1a_reflect', tenant_id: 'ten_demo', test_run_id: 'run_f1a_reflect', target_id: 'tgt_1', check_id: 'reflect.ssdp_exposure.safe',
      source: 'probe_worker', signal_type: 'probe_result', producer_kind: 'signed_probe', nonce_hash: 'nh_reflect', timestamp: NOW.toISOString(),
      metadata: { probe_kind: 'reflection_service_probe', protocol: 'udp', port: 1900, udp_outcome: 'validated_reply', service_validated: true,
        peer_is_cdn: false, sample_agreement: 'agree', payload_profile: 'ssdp_msearch', safety_attestation: { probe_requests_sent: 1 } },
    });
    const finalized = finalizeTestRun({ tenantId: 'ten_demo', userId: 'u1', role: 'engineer' }, 'run_f1a_reflect', { force: true });
    assert.equal(finalized.verdict.verdict, 'exposed', JSON.stringify(finalized));
    assert.equal(finalized.verdict.exposure_basis, 'validated_reflector_reply');
    assert.equal(finalized.verdict.placement_confidence.exposure_basis, 'validated_reflector_reply');
  });
});
