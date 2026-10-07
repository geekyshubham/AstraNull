import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  REQUIRED_LIMITATIONS,
  normalizeFirewallExpectation,
  validateComparisonEvaluation,
  verifyBaselineDigest,
  firewallBaselineCaptureDigest,
} from '../../src/contracts/protectionValidation.mjs';
import { EXTERNAL_OBSERVATION_SEMANTICS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import {
  FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
  buildFirewallBaselineCapture,
  classifyFirewallSample,
  evaluateFirewallChange,
  firewallSampleFromProbeEvent,
} from '../../src/lib/firewallChangeAcceptance.mjs';

const TENANT = 'ten_1';
const SOURCE = 'public-worker-eu';
const SOURCES = { worker_eu_1: SOURCE, worker_eu_2: SOURCE, worker_us_1: 'public-worker-us' };
const PRE_DAY = '2026-10-01';
const POST_DAY = '2026-10-03';
const TARGETS = {
  tgt_fw: { id: 'tgt_fw', tenant_id: TENANT, value: 'fw.example.test:443' },
  tgt_ssh: { id: 'tgt_ssh', tenant_id: TENANT, value: 'fw.example.test:22' },
  tgt_dns: { id: 'tgt_dns', tenant_id: TENANT, value: 'ns.example.test:53' },
  tgt_old: { id: 'tgt_old', tenant_id: TENANT, value: 'old.example.test:443' },
  tgt_new: { id: 'tgt_new', tenant_id: TENANT, value: 'new.example.test:443' },
};
const CHECKS = {
  tcp_connect: 'l3.forbidden_tcp_port.safe',
  udp_probe: 'l3.forbidden_udp_port.safe',
  tls_audit: 'tls.full_audit.safe',
  host_sni_bypass: 'origin.direct_reachability.safe',
  port_scan_bounded: 'l3.firewall_exposure_scan.safe',
};

function expectation(overrides = {}, { id = 'fwx_1', status = 'active' } = {}) {
  const record = normalizeFirewallExpectation({
    destination_target_id: 'tgt_fw',
    protocol: 'tcp',
    port: 443,
    expected: 'allow',
    source_perspective: SOURCE,
    change_id: 'CHG-1001',
    ...overrides,
  }, { tenantId: TENANT });
  return { ...record, id, status };
}

let seq = 0;
function sample({
  kind = 'tcp_connect',
  result = 'connected',
  metadata = {},
  target = 'tgt_fw',
  runId = null,
  day = PRE_DAY,
  minute = 0,
  worker = 'worker_eu_1',
  runStatus = 'verdicted',
  checkVersion = '1.0.0',
  producer = 'signed_probe',
  requests = 1,
  source,
} = {}) {
  seq += 1;
  const run = {
    id: runId ?? `run_${seq}`,
    tenant_id: TENANT,
    target_id: target,
    check_id: CHECKS[kind],
    status: runStatus,
    check_version: checkVersion,
    scenario_version: null,
  };
  const event = {
    id: `evt_${seq}`,
    tenant_id: TENANT,
    test_run_id: run.id,
    target_id: target,
    check_id: run.check_id,
    signal_type: 'probe_result',
    producer_kind: producer,
    timestamp: `${day}T00:${String(minute).padStart(2, '0')}:00.000Z`,
    metadata: {
      profile_kind: kind,
      probe_kind: kind,
      external_result: result,
      probe_worker_id: worker,
      safety_attestation: { requests_sent: requests, duration_ms: 5 },
      ...metadata,
    },
  };
  return firewallSampleFromProbeEvent({
    event,
    run,
    target: TARGETS[target],
    verdictId: `verdict_${seq}`,
    sourcePerspective: source === undefined ? (SOURCES[worker] ?? null) : source,
  });
}

function tls(opts = {}) {
  return sample({ kind: 'tls_audit', result: 'blocked', metadata: { tls_protocol: 'TLSv1.3' }, ...opts });
}

function origin(outcome, statusCode, opts = {}, scopePath = '/health', extra = {}) {
  return sample({
    kind: 'host_sni_bypass',
    result: outcome === 'explicit_denial_observed' ? 'blocked' : 'connected',
    metadata: {
      origin_observation: {
        semantics_version: EXTERNAL_OBSERVATION_SEMANTICS_VERSION,
        outcome,
        status_code: statusCode,
        limitations: statusCode >= 500 ? ['generic_error_response'] : [],
        scope: { host: 'fw.example.test', path: scopePath, port: 443 },
        ...extra,
      },
    },
    ...opts,
  });
}

function capture(expectations, samples, extra = {}) {
  return buildFirewallBaselineCapture({
    tenantId: TENANT,
    changeId: 'CHG-1001',
    expectations: expectations.map((record) => ({ id: record.id, record })),
    samples,
    freshnessWindowSeconds: 2592000,
    capturedAt: '2026-10-02T00:00:00.000Z',
    ...extra,
  }).capture;
}

function evaluate(expectations, preSamples, postSamples, extra = {}) {
  const baseline = { id: 'fwb_1', ...capture(expectations, preSamples) };
  return evaluateFirewallChange({
    tenantId: TENANT,
    baseline,
    expectations: Object.fromEntries(expectations.map((record) => [record.id, record])),
    candidateSamples: postSamples,
    evaluatedAt: '2026-10-04T00:00:00.000Z',
    now: '2026-10-04T00:00:00.000Z',
    ...extra,
  });
}

function only(result) {
  assert.equal(result.evaluation.items.length, 1);
  return result.evaluation.items[0];
}

describe('classifyFirewallSample', () => {
  const tcpAllow = expectation();

  it('treats a port connect as transport reachability only (E2, outside readiness)', () => {
    const verdict = classifyFirewallSample(tcpAllow, sample());
    assert.equal(verdict.observation_class, 'reachable_transport_only');
    assert.equal(verdict.evidence_tier, 'E2');
    assert.equal(verdict.readiness_coverage, false);
  });

  it('never maps timeouts, refusals or unreachable to a denial', () => {
    assert.equal(classifyFirewallSample(tcpAllow, sample({ result: 'timeout' })).observation_class, 'no_response');
    for (const code of ['ECONNREFUSED', 'EHOSTUNREACH', 'ECONNRESET']) {
      const verdict = classifyFirewallSample(tcpAllow, sample({ result: code === 'ECONNRESET' ? 'error' : 'blocked', metadata: { error_class: code } }));
      assert.equal(verdict.observation_class, 'transport_error', code);
    }
  });

  it('marks probes that sent no request as not tested', () => {
    assert.equal(classifyFirewallSample(tcpAllow, sample({ requests: 0, result: 'error' })).observation_class, 'not_tested');
    assert.equal(classifyFirewallSample(tcpAllow, sample({ result: 'not_run' })).observation_class, 'not_tested');
  });

  it('ignores untrusted producers and samples from another endpoint', () => {
    assert.equal(classifyFirewallSample(tcpAllow, sample({ producer: 'internal_simulation' })).reason, 'untrusted_producer');
    assert.equal(classifyFirewallSample(tcpAllow, sample({ metadata: { target_port: 8443 } })).reason, 'endpoint_mismatch');
    assert.equal(classifyFirewallSample(expectation({ protocol: 'udp', port: 443 }), sample()).reason, 'protocol_mismatch');
  });

  it('only semantic checks yield a valid service response', () => {
    const verdict = classifyFirewallSample(tcpAllow, tls());
    assert.equal(verdict.observation_class, 'service_response_observed');
    assert.equal(verdict.evidence_tier, 'E3');
    const udp = expectation({ protocol: 'udp', port: 53, destination_target_id: 'tgt_dns' });
    assert.equal(classifyFirewallSample(udp, sample({ kind: 'udp_probe', target: 'tgt_dns' })).observation_class, 'reachable_transport_only');
    assert.equal(classifyFirewallSample(udp, sample({ kind: 'udp_probe', target: 'tgt_dns', result: 'timeout' })).observation_class, 'udp_silence');
  });

  it('maps origin observations to service classes and keeps 5xx transport-only', () => {
    const service = expectation({ protocol: 'service', port: undefined, service_endpoint: { service: 'https', port: 443, path: '/health' } });
    assert.equal(classifyFirewallSample(service, origin('response_observed', 200)).observation_class, 'service_response_observed');
    assert.equal(classifyFirewallSample(service, origin('response_observed', 502)).observation_class, 'reachable_transport_only');
    for (const status of [401, 403, 404]) {
      assert.equal(classifyFirewallSample(service, origin('response_observed', status)).observation_class, 'service_response_observed', String(status));
    }
    assert.equal(classifyFirewallSample(service, origin('explicit_denial_observed', 403)).observation_class, 'service_response_observed');
    assert.equal(classifyFirewallSample(service, origin('misdirected_request', 421)).observation_class, 'service_response_observed');
    const proxied = classifyFirewallSample(service, origin('probe_path_error', 407));
    assert.equal(proxied.observation_class, 'not_tested');
    assert.equal(proxied.sample_reason, 'probe_path_error');
    assert.equal(classifyFirewallSample(service, origin('not_applicable', 403)).sample_reason, 'cdn_edge_ip');
    const refused = classifyFirewallSample(service, origin('transport_error', null, {}, '/health', { error_reason: 'connection_refused' }));
    assert.equal(refused.observation_class, 'transport_error');
    assert.equal(refused.denial_basis, 'connection_refused');
    assert.equal(classifyFirewallSample(service, origin('no_response', null)).observation_class, 'no_response');
    assert.equal(classifyFirewallSample(service, origin('response_observed', 200, {}, '/other')).reason, 'endpoint_mismatch');
    assert.equal(classifyFirewallSample(service, tls()).reason, 'path_not_observed_by_check');
  });

  it('reads bounded port scans per declared port only', () => {
    const ssh = expectation({ port: 22, destination_target_id: 'tgt_ssh' });
    assert.equal(classifyFirewallSample(ssh, sample({ kind: 'port_scan_bounded', target: 'tgt_ssh', metadata: { open_ports: [22] } })).observation_class, 'reachable_transport_only');
    assert.equal(classifyFirewallSample(ssh, sample({ kind: 'port_scan_bounded', target: 'tgt_ssh', result: 'blocked', metadata: { open_ports: [], filtered_ports: [22] } })).observation_class, 'no_response');
    assert.equal(classifyFirewallSample(ssh, sample({ kind: 'port_scan_bounded', target: 'tgt_ssh', metadata: { open_ports: [3389] } })).reason, 'endpoint_not_sampled');
    const closed = classifyFirewallSample(ssh, sample({ kind: 'port_scan_bounded', target: 'tgt_ssh', result: 'blocked', metadata: { open_ports: [], closed_ports: [22] } }));
    assert.equal(closed.observation_class, 'transport_error');
    assert.equal(closed.denial_basis, 'connection_refused');
  });
});

describe('required allow', () => {
  it('a single refusal remains unverified, while repeated refusals show service unavailability', () => {
    const exp = expectation();
    const item = only(evaluate([exp], [tls()], [sample({ kind: 'tls_audit', day: POST_DAY, result: 'error', metadata: { error_class: 'ECONNREFUSED' } })]));
    assert.equal(item.status, 'inconclusive');
    assert.equal(item.post_state, 'unverified');
    assert.ok(item.reasons.includes('rst_after_change'));
    const repeated = only(evaluate([exp], [tls()], [
      sample({ kind: 'tls_audit', day: POST_DAY, result: 'error', metadata: { error_class: 'ECONNREFUSED' } }),
      sample({ kind: 'tls_audit', day: POST_DAY, minute: 1, result: 'error', metadata: { error_class: 'ECONNREFUSED' } }),
    ]));
    assert.equal(repeated.status, 'regression');
    assert.equal(repeated.gap_kind, 'required_service_newly_unavailable');
    assert.equal(repeated.post_state, 'not_observed');
  });

  it('a port connect alone never matches a required allow', () => {
    const exp = expectation();
    const item = only(evaluate([exp], [sample(), sample({ minute: 1 })], [sample({ day: POST_DAY }), sample({ day: POST_DAY, minute: 1 })]));
    assert.equal(item.status, 'inconclusive');
    assert.ok(item.reasons.includes('service_response_required'));
    assert.equal(item.expectation_met, null);
  });

  it('matches on valid service responses and is accepted with the firewall limitations', () => {
    const exp = expectation();
    const result = evaluate([exp], [tls()], [tls({ day: POST_DAY })]);
    const item = only(result);
    assert.equal(item.status, 'matched');
    assert.equal(item.expectation_met, true);
    assert.equal(item.evidence_refs.length, 1);
    for (const limitation of REQUIRED_LIMITATIONS.firewall_change) assert.ok(item.limitations.includes(limitation));
    assert.equal(result.evaluation.summary.accepted, true);
    assert.match(result.statement.headline, /Sampled public-ingress behaviour/);
    assert.match(result.statement.not_established, /rule-table, routing, NAT, egress and east-west equivalence are not established/);
    assert.equal(result.statement.readiness_effect, 'none');
    assert.equal(validateComparisonEvaluation({ ...result.evaluation }).ok, true);
  });

  it('reports a required service newly unavailable only after repeated silence', () => {
    const exp = expectation();
    const regression = only(evaluate([exp], [tls()], [tls({ day: POST_DAY, result: 'timeout', metadata: { tls_protocol: null } }), tls({ day: POST_DAY, minute: 1, result: 'timeout', metadata: { tls_protocol: null } })]));
    assert.equal(regression.status, 'regression');
    assert.equal(regression.gap_kind, 'required_service_newly_unavailable');
    assert.equal(regression.expectation_met, false);
    assert.ok(!('rule_id' in regression));
    const single = only(evaluate([exp], [tls()], [tls({ day: POST_DAY, result: 'timeout', metadata: { tls_protocol: null } })]));
    assert.equal(single.status, 'inconclusive');
    assert.ok(single.reasons.includes('single_sample_not_unavailability'));
  });

  it('keeps mixed post samples inconclusive and visible', () => {
    const exp = expectation();
    const result = evaluate([exp], [tls()], [tls({ day: POST_DAY }), tls({ day: POST_DAY, minute: 1, result: 'timeout', metadata: { tls_protocol: null } })]);
    const item = only(result);
    assert.equal(item.status, 'inconclusive');
    assert.ok(item.reasons.includes('mixed_samples'));
    assert.deepEqual(result.observations[0].post.classes, ['no_response', 'service_response_observed']);
    assert.equal(result.evaluation.summary.accepted, false);
  });
});

describe('expected deny', () => {
  const ssh = () => expectation({ port: 22, expected: 'deny', destination_target_id: 'tgt_ssh' });
  const sshSample = (opts) => sample({ target: 'tgt_ssh', ...opts });

  it('flags a forbidden service newly reachable without claiming a rule or root cause', () => {
    const item = only(evaluate([ssh()],
      [sshSample({ result: 'timeout' }), sshSample({ result: 'timeout', minute: 1 })],
      [sshSample({ day: POST_DAY })]));
    assert.equal(item.status, 'regression');
    assert.equal(item.gap_kind, 'forbidden_service_newly_reachable');
    assert.equal(item.pre_state, 'not_observed');
    assert.equal(item.post_state, 'violated');
    assert.ok(item.reasons.includes('baseline_denial_not_control_specific'));
  });

  it('never accepts silence as control-specific denial', () => {
    const result = evaluate([ssh()],
      [sshSample({ result: 'timeout' }), sshSample({ result: 'timeout', minute: 1 })],
      [sshSample({ day: POST_DAY, result: 'timeout' }), sshSample({ day: POST_DAY, minute: 1, result: 'blocked', metadata: { error_class: 'ECONNREFUSED' } })]);
    const item = only(result);
    assert.equal(item.status, 'inconclusive');
    assert.ok(item.reasons.includes('control_specific_denial_required'));
    assert.equal(result.evaluation.summary.accepted, false);
  });

  it('treats any HTTP reply on a forbidden service endpoint, including 401/403/421, as reachable', () => {
    const exp = expectation({ protocol: 'service', port: undefined, expected: 'deny', service_endpoint: { service: 'https', port: 443, path: '/health' } });
    for (const [outcome, status] of [['response_observed', 401], ['response_observed', 403], ['misdirected_request', 421], ['explicit_denial_observed', 403]]) {
      const item = only(evaluate([exp], [origin(outcome, status)], [origin(outcome, status, { day: POST_DAY })]));
      assert.equal(item.status, 'matched', `${outcome} ${status}`);
      assert.equal(item.post_state, 'violated');
      assert.equal(item.expectation_met, false);
    }
  });

  it('never confirms firewall enforcement from a refusal even when the port was previously open', () => {
    const fixed = only(evaluate([ssh()],
      [sshSample({ result: 'connected' })],
      [sshSample({ day: POST_DAY, result: 'blocked', metadata: { error_class: 'ECONNREFUSED' } })]));
    assert.equal(fixed.status, 'inconclusive');
    assert.equal(fixed.post_state, 'unverified');
    assert.equal(fixed.expectation_met, null);
    assert.ok(fixed.reasons.includes('rst_after_change'));
    const noBaseline = only(evaluate([ssh()],
      [sshSample({ result: 'timeout' }), sshSample({ result: 'timeout', minute: 1 })],
      [sshSample({ day: POST_DAY, result: 'blocked', metadata: { error_class: 'ECONNREFUSED' } })]));
    assert.equal(noBaseline.status, 'inconclusive');
    assert.ok(noBaseline.reasons.includes('rst_without_open_baseline'));
  });

  it('accepts an ICMP administratively-prohibited reply as control-specific denial', () => {
    const item = only(evaluate([ssh()],
      [sshSample({ result: 'connected' })],
      [sshSample({ day: POST_DAY, result: 'error', metadata: { error_class: 'EHOSTUNREACH', icmp_type: 3, icmp_code: 13 } })]));
    assert.equal(item.status, 'improvement');
    assert.equal(item.post_state, 'satisfied');
    assert.ok(item.reasons.includes('icmp_admin_prohibited'));
  });

  it('keeps UDP silence ambiguous', () => {
    const udp = expectation({ protocol: 'udp', port: 53, expected: 'deny', destination_target_id: 'tgt_dns' });
    const silent = (opts) => sample({ kind: 'udp_probe', target: 'tgt_dns', result: 'timeout', ...opts });
    const result = evaluate([udp], [silent(), silent({ minute: 1 })], [silent({ day: POST_DAY }), silent({ day: POST_DAY, minute: 1 })]);
    const item = only(result);
    assert.equal(item.status, 'inconclusive');
    assert.ok(item.limitations.includes('udp_silence_ambiguous'));
    assert.ok(result.evaluation.limitations.includes('udp_silence_ambiguous'));
  });
});

describe('compatibility', () => {
  const exp = () => expectation();

  it('fails when the post evidence was observed from another source', () => {
    const item = only(evaluate([exp()], [tls()], [tls({ day: POST_DAY, worker: 'worker_us_1' })]));
    assert.equal(item.status, 'not_comparable');
    assert.ok(item.compatibility_reasons.includes('source_mismatch'));
  });

  it('fails when the post worker is not an approved source', () => {
    const item = only(evaluate([exp()], [tls()], [tls({ day: POST_DAY, worker: 'worker_unknown', source: null })]));
    assert.equal(item.status, 'not_comparable');
    assert.ok(item.compatibility_reasons.includes('source_missing'));
  });

  it('accepts repeated samples from approved workers of the same source and keeps worker identity', () => {
    const result = evaluate([exp()],
      [tls(), tls({ worker: 'worker_eu_2', minute: 1 })],
      [tls({ day: POST_DAY }), tls({ day: POST_DAY, worker: 'worker_eu_2', minute: 1 })]);
    const item = only(result);
    assert.equal(item.status, 'matched');
    assert.deepEqual(result.observations[0].post.worker_ids, ['worker_eu_1', 'worker_eu_2']);
    assert.deepEqual(item.evidence_refs.map((ref) => ref.worker_id).sort(), ['worker_eu_1', 'worker_eu_2']);
  });

  it('never passes unfinished, version-mismatched, or stale evidence', () => {
    const unfinished = only(evaluate([exp()], [tls()], [tls({ day: POST_DAY, runStatus: 'collecting' })]));
    assert.equal(unfinished.status, 'not_comparable');
    assert.ok(unfinished.compatibility_reasons.includes('evidence_not_finalized'));
    const version = only(evaluate([exp()], [tls()], [tls({ day: POST_DAY, checkVersion: '2.0.0' })]));
    assert.equal(version.status, 'not_comparable');
    assert.ok(version.compatibility_reasons.includes('check_version_mismatch'));
    const stale = evaluate([exp()], [tls()], [tls({ day: '2026-11-20' })], { evaluatedAt: '2026-11-21T00:00:00.000Z', now: '2026-11-21T00:00:00.000Z' });
    assert.equal(only(stale).status, 'stale');
    assert.equal(stale.evaluation.summary.accepted, false);
  });

  it('treats an undeclared destination change as not comparable', () => {
    const migrated = only(evaluate([exp()], [tls()], [tls({ day: POST_DAY, target: 'tgt_new' })]));
    assert.equal(migrated.status, 'not_comparable');
    assert.ok(migrated.compatibility_reasons.includes('destination_mapping_missing'));
    const pinned = only(evaluate([exp()],
      [tls({ metadata: { tls_protocol: 'TLSv1.3', pinned_address: '192.0.2.10' } })],
      [tls({ day: POST_DAY, metadata: { tls_protocol: 'TLSv1.3', pinned_address: '198.51.100.20' } })]));
    assert.equal(pinned.status, 'not_comparable');
    assert.ok(pinned.compatibility_reasons.includes('destination_mismatch'));
  });

  it('compares across an explicit customer-declared pre/post mapping', () => {
    const mapped = expectation({
      destination_target_id: 'tgt_new',
      pre_post_mapping: { pre_destination_target_id: 'tgt_old', post_destination_target_id: 'tgt_new', declared_by_customer: true },
    });
    const item = only(evaluate([mapped], [tls({ target: 'tgt_old' })], [tls({ day: POST_DAY, target: 'tgt_new' })]));
    assert.equal(item.status, 'matched');
  });

  it('rejects changed expectations and tampered baselines', () => {
    const original = exp();
    const baseline = { id: 'fwb_1', ...capture([original], [tls()]) };
    const run = (expectations, base = baseline) => only(evaluateFirewallChange({
      tenantId: TENANT,
      baseline: base,
      expectations,
      candidateSamples: [tls({ day: POST_DAY })],
      evaluatedAt: '2026-10-04T00:00:00.000Z',
    }));
    assert.ok(run({ fwx_1: { ...original, status: 'archived' } }).compatibility_reasons.includes('expectation_mismatch'));
    assert.ok(run({ fwx_1: { ...original, expected: 'deny' } }).compatibility_reasons.includes('expectation_digest_mismatch'));
    const tampered = {
      ...baseline,
      entries: baseline.entries.map((entry) => ({ ...entry, observations: entry.observations.map((obs) => ({ ...obs, observation_class: 'explicit_denial_observed' })) })),
    };
    const item = run({ fwx_1: original }, tampered);
    assert.equal(item.status, 'not_comparable');
    assert.ok(item.compatibility_reasons.includes('invalid_baseline'));
    const missing = run({});
    assert.equal(missing.status, 'not_comparable');
  });
});

describe('summaries', () => {
  it('reports not_tested when no post evidence was selected and never accepts it', () => {
    const result = evaluate([expectation()], [tls()], []);
    assert.equal(only(result).status, 'not_tested');
    assert.equal(result.evaluation.summary.evaluated, 0);
    assert.equal(result.evaluation.summary.accepted, false);
  });

  it('zero evaluated expectations is never success', () => {
    const result = evaluateFirewallChange({ tenantId: TENANT, baseline: { id: 'fwb_x', entries: [] }, evaluatedAt: '2026-10-04T00:00:00.000Z' });
    assert.equal(result.evaluation.summary.total, 0);
    assert.equal(result.evaluation.summary.accepted, false);
    assert.match(result.statement.headline, /not an acceptance/);
  });

  it('lists active expectations of the change that were not baselined', () => {
    const exp = expectation();
    const extra = expectation({ port: 22, destination_target_id: 'tgt_ssh', expected: 'deny' }, { id: 'fwx_2' });
    const result = evaluate([exp], [tls()], [tls({ day: POST_DAY })], { extraExpectations: [exp, extra] });
    assert.equal(result.evaluation.items.length, 2);
    const missing = result.evaluation.items.find((item) => item.expectation_id === 'fwx_2');
    assert.equal(missing.status, 'not_tested');
    assert.deepEqual(missing.reasons, ['not_in_baseline']);
    assert.equal(result.evaluation.summary.accepted, false);
  });
});

describe('baseline capture', () => {
  it('pins expectation version, digests, sources, workers and observations', () => {
    const exp = expectation();
    const record = capture([exp], [tls(), tls({ worker: 'worker_eu_2', minute: 1 })]);
    assert.equal(record.baseline_digest, firewallBaselineCaptureDigest(record));
    const [entry] = record.entries;
    assert.equal(verifyBaselineDigest(entry), true);
    assert.equal(entry.expectation_version, 1);
    assert.equal(entry.expectation_digest, exp.digest);
    assert.equal(entry.classifier_version, FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION);
    assert.equal(entry.references.length, 2);
    assert.ok(entry.references.every((ref) => ref.source_perspective === SOURCE && ref.worker_id && ref.finalized));
    assert.equal(entry.observations.length, 2);
    assert.match(entry.observations_digest, /^[a-f0-9]{64}$/);
  });

  it('rejects unfinished, unsourced, wrong-source, unrelated and cross-change evidence', () => {
    const exp = expectation();
    assert.throws(() => capture([exp], [tls({ runStatus: 'running' })]), (err) => err.code === 'evidence_not_finalized' && err.status === 409);
    assert.throws(() => capture([exp], [tls({ worker: 'worker_unknown', source: null })]), (err) => err.code === 'invalid_comparison_baseline');
    assert.throws(() => capture([exp], [tls({ worker: 'worker_us_1' })]), (err) => err.code === 'invalid_comparison_baseline');
    assert.throws(() => capture([exp], [tls({ target: 'tgt_new' })]), (err) => err.code === 'invalid_comparison_baseline');
    assert.throws(() => capture([exp], [sample({ requests: 0, result: 'error' })]), (err) => err.code === 'invalid_comparison_baseline');
    const other = { ...exp, change_id: 'CHG-9' };
    assert.throws(() => capture([other], [tls()]), (err) => err.code === 'invalid_comparison_baseline');
    assert.throws(() => capture([{ ...exp, status: 'archived' }], [tls()]), (err) => err.status === 409);
  });
});
