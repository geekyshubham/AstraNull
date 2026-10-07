import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { probeHostSniBypass } from '../../src/lib/capabilityProbes.mjs';
import { presentTargetEdgeDetection } from '../../src/lib/edgeDetectionPresenter.mjs';
import { edgeDetectionRowFields, projectEdgeDetection } from '../../src/lib/edgeDetectionProjection.mjs';
import {
  EXTERNAL_OBSERVATION_LABELS,
  EXTERNAL_OBSERVATION_OUTCOMES,
  classifyDirectOriginObservation,
  metadataConfirmsApplicationBypass,
  metadataConfirmsOriginLockdown,
  matchControlDenialSignature,
  originObservationOf,
} from '../../src/lib/externalObservationOutcomes.mjs';
import { runOutsideInWafScan } from '../../src/lib/outsideInWafScanner.mjs';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';
import { buildWafEvidenceCorroboration } from '../../src/lib/wafProtectedEvidence.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { assessOriginReachability } from '../../src/services/originBindings.mjs';
import { originOutcomeFromProbe } from '../../src/services/targetHistory.mjs';
import { originIdentityLabel, originObservationLabel } from '../../apps/web/react/src/lib/origin-observation.mjs';
import { inconclusiveReason } from '../../src/lib/inconclusiveReasons.mjs';

const EDGE_URL = 'https://edge.example.test/';
const NONCE = 'nonce-pv01-synthetic';

it('does not mistake a generic AWS storage authorization error for WAF enforcement', () => {
  assert.equal(matchControlDenialSignature({ statusCode: 403, bodyText: '<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>' }), null);
});

function mockResponse(status, headers = {}) {
  const normalized = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const bytes = new TextEncoder().encode(normalized.__body ?? '');
  return {
    status,
    headers: {
      get: (name) => normalized[String(name).toLowerCase()] ?? null,
      forEach: (fn) => { for (const [name, value] of Object.entries(normalized)) fn(value, name); },
    },
    body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
  };
}

function edgeFetch({ baselineStatus = 200, server = 'cloudflare' } = {}) {
  return async (url, init) => {
    const isBaseline = url === EDGE_URL && init?.headers?.['User-Agent'] && init?.method !== 'POST';
    if (isBaseline) return mockResponse(baselineStatus, { server, 'cf-ray': '1' });
    return mockResponse(403, { server, 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
  };
}

function scan({ originBypassFn, baselineStatus, server, canaryNonce } = {}) {
  return runOutsideInWafScan({
    url: EDGE_URL,
    budget: 13,
    timeoutMs: 1000,
    directIp: '198.51.100.7',
    hostname: 'edge.example.test',
    fetchFn: edgeFetch({ baselineStatus, server }),
    originBypassFn,
    ...(canaryNonce ? { canaryNonce } : {}),
  });
}

function asProbeMetadata(outcome) {
  return { ...outcome, probe_kind: 'outside_in_waf_scan', profile_kind: 'outside_in_waf_scan' };
}

function hostSniJob(extra = {}) {
  return {
    nonce: NONCE,
    constraints: { timeout_ms: 1000, max_requests: 1 },
    target: { kind: 'fqdn', value: 'edge.example.test' },
    probe_profile: {
      kind: 'host_sni_bypass',
      protected_host: 'edge.example.test',
      direct_ip: '198.51.100.7',
      marker: 'astranull-safe-marker',
    },
    ...extra,
  };
}

function correlateHostSni(outcome) {
  return correlateExternalOnlyVerdict({
    externalResult: outcome.external_result,
    expectedBehavior: 'must_block_before_origin',
    probeKind: 'host_sni_bypass',
    probeIoObserved: true,
    probeMetadata: outcome.metadata,
  });
}

describe('PV-01 negative regressions: silence and errors never establish protection', () => {
  for (const [name, error] of [
    ['timeout', Object.assign(new Error('timed out'), { name: 'AbortError' })],
    ['deadline', Object.assign(new Error('deadline'), { code: 'probe_job_deadline_exceeded' })],
    ['refusal', Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })],
    ['tls failure', Object.assign(new Error('tls'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })],
  ]) {
    it(`scanner origin-leg ${name} never yields origin lockdown or a Protected label`, async () => {
      const outcome = await scan({ originBypassFn: async () => ({ res: null, error }) });
      assert.equal(outcome.origin_lockdown_confirmed, false);
      assert.notEqual(outcome.posture_label, 'Protected');
      assert.notEqual(outcome.posture_status, 'protected');
      assert.equal(outcome.posture_status, 'edge_protected');
      assert.equal(outcome.network_firewall.status, 'inconclusive');
      assert.ok(['no_response', 'transport_error'].includes(outcome.origin_observation.outcome));
      assert.equal(outcome.network_firewall.direct_origin_reachability.outcome, outcome.origin_observation.outcome);

      const projection = projectEdgeDetection(asProbeMetadata(outcome));
      assert.notEqual(projection.protection.status, 'protected');
      assert.equal(projection.protection.origin_lockdown_confirmed, false);
      assert.equal(projection.network_firewall.direct_origin_reachability.status, 'inconclusive');

      const bound = deriveWafSignalsFromBoundEvents({
        probes: [{ id: 'evt_1', nonce_hash: 'sha256:n', metadata: { ...asProbeMetadata(outcome), external_result: 'blocked' } }],
      });
      assert.equal(bound.originLockdownConfirmed, false);
      assert.equal(bound.validationPassed, false);
      assert.equal(buildWafEvidenceCorroboration({
        probes: [{ id: 'evt_1', nonce_hash: 'sha256:n', metadata: asProbeMetadata(outcome) }],
      }).originLockdownConfirmed, false);
    });
  }

  for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH', 'ECONNRESET']) {
    it(`standalone origin executor ${code} is a transport error, never blocked or edge_protected`, async () => {
      const outcome = await probeHostSniBypass(hostSniJob(), {
        fetchFn: async () => { throw Object.assign(new Error(code), { code }); },
      });
      assert.equal(outcome.external_result, 'error');
      assert.equal(outcome.metadata.origin_observation.outcome, 'transport_error');
      assert.equal(outcome.metadata.application_bypass_confirmed, false);
      const verdict = correlateHostSni(outcome);
      assert.notEqual(verdict.verdict, 'edge_protected');
      assert.equal(verdict.verdict, 'inconclusive');
      assert.equal(originOutcomeFromProbe({ ...outcome.metadata, external_result: outcome.external_result }), 'transport_failure');
      assert.equal(originObservationLabel(outcome.metadata), 'Transport error; enforcement unverified');
      const reason = inconclusiveReason({ probeKind: 'host_sni_bypass', externalResult: 'error', metadata: outcome.metadata });
      assert.equal(reason.reason, 'origin_transport_error');
      assert.doesNotMatch(verdict.explanation, /protected|lockdown confirmed/i);
    });
  }

  it('standalone origin executor timeout is no response and inconclusive', async () => {
    const outcome = await probeHostSniBypass(hostSniJob(), {
      fetchFn: async () => { throw Object.assign(new Error('timed out'), { name: 'AbortError' }); },
    });
    assert.notEqual(outcome.external_result, 'blocked');
    assert.equal(correlateHostSni(outcome).verdict, 'inconclusive');
    assert.equal(originOutcomeFromProbe({ ...outcome.metadata, external_result: outcome.external_result }), 'timeout');
    if (outcome.metadata.origin_observation) {
      assert.equal(originObservationLabel(outcome.metadata), 'No response; enforcement unverified');
    }
  });

  it('standalone origin executor 5xx generic error page never establishes protection', async () => {
    for (const status of [500, 502, 503]) {
      const outcome = await probeHostSniBypass(hostSniJob(), {
        fetchFn: async () => mockResponse(status, { server: 'nginx' }),
      });
      assert.notEqual(outcome.external_result, 'blocked');
      assert.equal(outcome.metadata.origin_observation.outcome, 'response_observed');
      assert.ok(outcome.metadata.origin_observation.limitations.includes('generic_error_response'));
      assert.equal(outcome.metadata.application_bypass_confirmed, false);
      assert.notEqual(correlateHostSni(outcome).verdict, 'edge_protected');
    }
  });

  it('legacy host/SNI blocked metadata without explicit denial evidence finalizes inconclusive', () => {
    const verdict = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeKind: 'host_sni_bypass',
      probeIoObserved: true,
      probeMetadata: { probe_kind: 'host_sni_bypass', error_class: undefined, bypass_signal: false },
    });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.equal(originOutcomeFromProbe({ external_result: 'blocked' }), null);
  });

  it('legacy origin_lockdown_confirmed flags without denial evidence are not trusted by consumers', () => {
    const legacy = { external_result: 'blocked', waf_fingerprint_detected: true, origin_lockdown_confirmed: true };
    assert.equal(metadataConfirmsOriginLockdown(legacy), false);
    assert.equal(deriveWafSignalsFromBoundEvents({
      probes: [{ id: 'evt_legacy', nonce_hash: 'sha256:l', metadata: legacy }],
    }).originLockdownConfirmed, false);
    assert.equal(buildWafEvidenceCorroboration({
      probes: [{ id: 'evt_legacy', nonce_hash: 'sha256:l', metadata: legacy }],
    }).originLockdownConfirmed, false);
  });

  it('a stored legacy protected row presents as edge-only without explicit denial basis', () => {
    const presented = presentTargetEdgeDetection({
      status: 'detected',
      waf_status: 'detected',
      waf_vendor: 'cloudflare',
      cdn_status: 'detected',
      evidence_json: {
        effectiveness: { status: 'effective_for_tested_probes', tested_count: 3, blocked_count: 3 },
        protection: { status: 'protected', origin_lockdown_confirmed: true },
        network_firewall: { status: 'inconclusive', direct_origin_reachability: { status: 'inconclusive' } },
      },
    });
    assert.equal(presented.protection.status, 'edge_protected');
    assert.equal(presented.protection.origin_lockdown_confirmed, false);
  });
});

describe('PV-01 negative regressions: header similarity never confirms bypass', () => {
  it('scanner shared Server header with a 200 direct response is suspected, not confirmed', async () => {
    const outcome = await scan({
      server: 'app-server-v2',
      originBypassFn: async () => ({ res: mockResponse(200, { server: 'app-server-v2' }), error: null }),
    });
    assert.equal(outcome.origin_bypass_application_signature_match, true);
    assert.equal(outcome.origin_bypass_confirmed, false);
    assert.equal(outcome.origin_bypass_suspected, true);
    assert.notEqual(outcome.posture_label, 'Bypass Risk');
    assert.notEqual(outcome.posture_label, 'Protected');
    assert.equal(outcome.network_firewall.status, 'exposed');
    assert.equal(outcome.network_firewall.direct_origin_reachability.application_bypass_confirmed, false);
    assert.deepEqual(outcome.origin_observation.supporting_signals, ['server_header_match']);
    assert.equal(metadataConfirmsApplicationBypass(asProbeMetadata(outcome)), false);
    const projection = projectEdgeDetection(asProbeMetadata(outcome));
    assert.equal(projection.network_firewall.direct_origin_reachability.application_bypass_confirmed, false);
  });

  it('scanner confirms bypass only from a nonce-bound canary echo over a healthy baseline', async () => {
    const outcome = await scan({
      canaryNonce: NONCE,
      originBypassFn: async ({ canaryNonce }) => ({
        res: mockResponse(200, { server: 'origin', 'x-astranull-canary-echo': canaryNonce }),
        error: null,
      }),
    });
    assert.equal(outcome.origin_observation.application_identity.method, 'nonce_canary');
    assert.equal(outcome.origin_bypass_confirmed, true);
    assert.equal(outcome.posture_label, 'Bypass Risk');
    assert.equal(metadataConfirmsApplicationBypass(asProbeMetadata(outcome)), true);
  });

  it('scanner does not confirm a canary bypass when the permitted-path baseline is unhealthy', async () => {
    const outcome = await scan({
      baselineStatus: 503,
      canaryNonce: NONCE,
      originBypassFn: async () => ({
        res: mockResponse(200, { 'x-astranull-canary-echo': NONCE }),
        error: null,
      }),
    });
    assert.equal(outcome.origin_observation.baseline, 'unhealthy');
    assert.equal(outcome.origin_bypass_confirmed, false);
    assert.equal(outcome.origin_bypass_suspected, true);
  });

  it('standalone executor shared Server header without echo stays reachability only', async () => {
    const outcome = await probeHostSniBypass(hostSniJob(), {
      fetchFn: async () => mockResponse(200, { server: 'app-server-v2' }),
    });
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.application_bypass_confirmed, false);
    assert.equal(outcome.metadata.origin_observation.outcome, 'response_observed');
    assert.match(correlateHostSni(outcome).explanation, /application identity was not confirmed/i);
  });

  it('standalone executor prefers the nonce-bound canary echo but stays suspected without a healthy baseline', async () => {
    const outcome = await probeHostSniBypass(hostSniJob(), {
      fetchFn: async (url, init) => mockResponse(200, {
        'x-astranull-canary-echo': init?.headers?.['x-astranull-nonce'],
        'x-astranull-marker-echo': 'astranull-safe-marker',
      }),
    });
    const observation = outcome.metadata.origin_observation;
    assert.equal(observation.application_identity.method, 'nonce_canary');
    assert.equal(observation.baseline, 'not_available');
    assert.equal(outcome.metadata.application_bypass_confirmed, false);
    assert.equal(outcome.metadata.application_bypass_suspected, true);
    assert.equal(metadataConfirmsApplicationBypass(outcome.metadata), false);
    const verdict = correlateHostSni(outcome);
    assert.equal(verdict.verdict, 'edge_exposed');
    assert.match(verdict.explanation, /suspected rather than confirmed/);
    assert.equal(originIdentityLabel(outcome.metadata), 'Confirmed by nonce-bound canary echo; no permitted-path baseline captured, bypass suspected');
  });

  it('an echo of the wrong nonce or a marker on a non-success response never confirms identity', async () => {
    const wrong = classifyDirectOriginObservation({
      response: mockResponse(200, { 'x-astranull-canary-echo': 'other-nonce' }),
      baseline: { status_code: 200 },
      expectedNonce: NONCE,
    });
    assert.equal(wrong.outcome, 'response_observed');
    assert.equal(wrong.application_bypass_confirmed, false);
    const errorPage = classifyDirectOriginObservation({
      response: mockResponse(502, { 'x-astranull-marker-echo': 'astranull-safe-marker' }),
      baseline: { status_code: 200 },
      expectedMarker: 'astranull-safe-marker',
    });
    assert.equal(errorPage.application_identity.confirmed, false);
    assert.equal(errorPage.application_bypass_suspected, false);
  });

  it('a static marker echo stays suspected even over a healthy baseline', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(200, { 'x-astranull-marker-echo': 'astranull-safe-marker' }),
      baseline: { status_code: 200 },
      expectedMarker: 'astranull-safe-marker',
      scope: { host: 'edge.example.test', path: '/login' },
    });
    assert.equal(observation.application_bypass_confirmed, false);
    assert.equal(observation.application_bypass_suspected, true);
    assert.equal(observation.application_identity.method, 'marker_echo');
    assert.ok(observation.limitations.includes('marker_echo_not_nonce_bound'));
    assert.equal(metadataConfirmsApplicationBypass({ origin_observation: { ...observation, application_bypass_confirmed: true } }), false);
    assert.ok(observation.limitations.includes('scoped_to_tested_host_path_source_time'));
    assert.equal(observation.scope.path, '/login');
    assert.equal(observation.control_identified, false);
  });

  it('a dropped-connection baseline is never healthy', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(403),
      baseline: { status_code: 200, connection_dropped: true },
    });
    assert.equal(observation.baseline, 'unhealthy');
    assert.equal(observation.origin_lockdown_confirmed, false);
  });
});

describe('PV-01 declared lockdown signature is the only lockdown basis', () => {
  const LOCKDOWN = { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } };

  it('scanner declared lockdown response with a healthy baseline confirms scoped lockdown', async () => {
    const outcome = await runOutsideInWafScan({
      url: EDGE_URL,
      budget: 13,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: edgeFetch(),
      declaredOriginLockdown: LOCKDOWN,
      originBypassFn: async () => ({ res: mockResponse(403, { server: 'origin-nginx', 'x-origin-lockdown': 'cdn-only' }), error: null }),
    });
    assert.equal(outcome.origin_observation.outcome, 'explicit_denial_observed');
    assert.deepEqual(outcome.origin_observation.denial_signature, { kind: 'declared', id: 'declared_response', vendor: null });
    assert.equal(outcome.origin_lockdown_confirmed, true);
    assert.equal(outcome.posture_label, 'Protected');
    assert.equal(outcome.origin_observation.control_identified, false);
    assert.equal(metadataConfirmsOriginLockdown(asProbeMetadata(outcome)), true);
    const projection = projectEdgeDetection(asProbeMetadata(outcome));
    assert.equal(projection.protection.status, 'protected');
    assert.equal(outcome.network_firewall.direct_origin_reachability.status, 'denied');
    assert.equal(projection.network_firewall.direct_origin_reachability.status, 'denied');
    assert.equal(projection.network_firewall.status, 'denied');
    const presented = presentTargetEdgeDetection({
      status: projection.status,
      waf_status: projection.waf.status,
      waf_vendor: projection.waf.vendor,
      cdn_status: projection.cdn.status,
      ...edgeDetectionRowFields(projection),
    });
    assert.equal(presented.protection.status, 'protected');
  });

  it('scanner undeclared 403 with a healthy baseline never confirms lockdown', async () => {
    const outcome = await scan({
      originBypassFn: async () => ({ res: mockResponse(403, { server: 'origin-nginx' }), error: null }),
    });
    assert.equal(outcome.origin_observation.outcome, 'response_observed');
    assert.equal(outcome.origin_observation.response_reason, 'unattributed_denial');
    assert.equal(outcome.origin_lockdown_confirmed, false);
    assert.notEqual(outcome.posture_label, 'Protected');
    assert.equal(metadataConfirmsOriginLockdown(asProbeMetadata(outcome)), false);
  });

  it('declared lockdown without a healthy baseline does not confirm lockdown', async () => {
    const outcome = await runOutsideInWafScan({
      url: EDGE_URL,
      budget: 13,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: edgeFetch({ baselineStatus: 503 }),
      declaredOriginLockdown: LOCKDOWN,
      originBypassFn: async () => ({ res: mockResponse(403, { 'x-origin-lockdown': 'cdn-only' }), error: null }),
    });
    assert.equal(outcome.origin_observation.outcome, 'explicit_denial_observed');
    assert.equal(outcome.origin_lockdown_confirmed, false);
    assert.notEqual(outcome.posture_label, 'Protected');
  });

  it('standalone executor 401/403/404 are origin responses, never denials or readiness credit', () => {
    return (async () => {
      for (const [status, headers, reason, verdictName, findings] of [
        [401, { 'www-authenticate': 'Basic realm="app"' }, 'authentication_challenge', 'edge_exposed', true],
        [403, {}, 'unattributed_denial', 'inconclusive', false],
        [404, {}, 'unattributed_denial', 'inconclusive', false],
      ]) {
        const outcome = await probeHostSniBypass(hostSniJob(), { fetchFn: async () => mockResponse(status, headers) });
        assert.equal(outcome.external_result, 'connected', String(status));
        assert.equal(outcome.metadata.origin_observation.outcome, 'response_observed');
        assert.equal(outcome.metadata.origin_observation.response_reason, reason);
        assert.equal(outcome.metadata.origin_observation.denial_signature, null);
        assert.equal(outcome.metadata.origin_observation.origin_lockdown_confirmed, false);
        const verdict = correlateHostSni(outcome);
        assert.equal(verdict.verdict, verdictName, String(status));
        assert.notEqual(verdict.verdict, 'edge_protected');
        assert.equal(verdict.createsFinding, findings);
        assert.equal(originOutcomeFromProbe({ ...outcome.metadata, external_result: outcome.external_result }), 'reachable');
      }
      const challenge = await probeHostSniBypass(hostSniJob(), { fetchFn: async () => mockResponse(401, {}) });
      assert.match(correlateHostSni(challenge).explanation, /authentication challenge observed/);
      assert.equal(originObservationLabel(challenge.metadata), 'Origin HTTP service reachable directly; authentication challenge observed');
    })();
  });

  it('421 and 407 are evidence gaps excluded from verdicts', async () => {
    for (const [status, outcomeName] of [[421, 'misdirected_request'], [407, 'probe_path_error']]) {
      const outcome = await probeHostSniBypass(hostSniJob(), { fetchFn: async () => mockResponse(status) });
      assert.equal(outcome.external_result, 'error');
      assert.equal(outcome.metadata.origin_observation.outcome, outcomeName);
      assert.equal(outcome.metadata.origin_observation.response_observed, false);
      const verdict = correlateHostSni(outcome);
      assert.equal(verdict.verdict, 'inconclusive');
      assert.equal(verdict.createsFinding, false);
      assert.match(verdict.explanation, /ignored for verdicts/);
      assert.equal(originOutcomeFromProbe({ ...outcome.metadata, external_result: outcome.external_result }), null);
    }
  });

  it('a vendor block signature on the direct path is a denial but never lockdown', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(200, { server: 'BigIP' }),
      bodyText: 'The requested URL was rejected. Please consult with your administrator. Your support ID is: 123',
      baseline: { status_code: 200 },
    });
    assert.equal(observation.outcome, 'explicit_denial_observed');
    assert.deepEqual(observation.denial_signature, { kind: 'vendor', id: 'f5_asm_rejection', vendor: 'f5' });
    assert.equal(observation.origin_lockdown_confirmed, false);
    const verdict = correlateHostSni({ external_result: 'blocked', metadata: { probe_kind: 'host_sni_bypass', origin_observation: observation } });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /customer-declared lockdown/);
  });

  it('declared lockdown over a healthy baseline is a scoped pass that does not identify the rule', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(403),
      bodyText: 'Access denied',
      baseline: { status_code: 200 },
      declaredLockdown: { status_code: 403, body_sha256: createHash('sha256').update('Access denied').digest('hex') },
      scope: { host: 'edge.example.test', path: '/' },
    });
    assert.equal(observation.origin_lockdown_confirmed, true);
    const verdict = correlateHostSni({ external_result: 'blocked', metadata: { probe_kind: 'host_sni_bypass', origin_observation: observation } });
    assert.equal(verdict.verdict, 'edge_protected');
    assert.match(verdict.explanation, /not identified/i);
    const wrongBody = classifyDirectOriginObservation({
      response: mockResponse(403),
      bodyText: 'Forbidden',
      baseline: { status_code: 200 },
      declaredLockdown: { status_code: 403, body_sha256: createHash('sha256').update('Access denied').digest('hex') },
    });
    assert.equal(wrongBody.outcome, 'response_observed');
  });

  it('an mTLS rejection counts only when mTLS was declared for the origin', () => {
    const error = Object.assign(new Error('alert'), { code: 'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED' });
    const declared = classifyDirectOriginObservation({ error, baseline: { status_code: 200 }, declaredLockdown: { mtls: true } });
    assert.equal(declared.outcome, 'explicit_denial_observed');
    assert.equal(declared.denial_signature.id, 'declared_mtls_rejection');
    assert.equal(declared.origin_lockdown_confirmed, true);
    const undeclared = classifyDirectOriginObservation({ error, baseline: { status_code: 200 } });
    assert.equal(undeclared.outcome, 'transport_error');
    assert.equal(undeclared.origin_lockdown_confirmed, false);
  });

  it('origin binding assessment never reports lockdown from a denied or reachable observation', () => {
    const binding = { id: 'ob_1', tenant_id: 't1', origin_target_id: 'tgt_origin', status: 'active', created_at: '2026-01-01T00:00:00.000Z', host: 'edge.example.test', sni: 'edge.example.test' };
    const row = {
      id: 'obs_1', tenant_id: 't1', target_id: 'tgt_origin', origin_binding_id: 'ob_1', family: 'origin_hosting',
      check_id: 'origin.host_sni_bypass.safe', producer_kind: 'signed_probe', attempt_class: 'successful',
      outcome: 'denied', observed_at: '2026-02-01T00:00:00.000Z', source_completed_at: '2026-02-01T00:00:01.000Z',
    };
    const assessed = assessOriginReachability(binding, [row], { verified: true });
    assert.equal(assessed.status, 'denied');
    assert.equal(assessed.lockdown, 'not_established');
  });

  it('re-reads a stored v1 status-only denial under current semantics without trusting it', () => {
    for (const [status, outcome] of [[401, 'response_observed'], [403, 'response_observed'], [421, 'misdirected_request']]) {
      const legacy = {
        external_result: 'blocked',
        origin_lockdown_confirmed: true,
        origin_observation: {
          semantics_version: 'external-observation-v1',
          outcome: 'explicit_denial_observed',
          status_code: status,
          baseline: 'healthy',
          origin_lockdown_confirmed: true,
          explicit_denial_observed: true,
          limitations: [],
        },
      };
      assert.equal(metadataConfirmsOriginLockdown(legacy), false, String(status));
      const reread = originObservationOf(legacy);
      assert.equal(reread.outcome, outcome);
      assert.equal(reread.denial_signature, null);
      assert.ok(reread.limitations.includes('legacy_status_only_denial_reclassified'));
      assert.notEqual(correlateHostSni({ external_result: 'blocked', metadata: { probe_kind: 'host_sni_bypass', ...legacy } }).verdict, 'edge_protected');
    }
  });
});

describe('PV-01 CDN-edge guard (aistripped.com fixtures, synthetic responses)', () => {
  it('a Cloudflare anycast address answering 403 error code 1003 is not an origin observation', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(403, { server: 'cloudflare', 'cf-ray': '1' }),
      bodyText: 'error code: 1003',
      baseline: { status_code: 200 },
      directAddress: '104.21.61.235',
      scope: { host: 'aistripped.com', path: '/' },
    });
    assert.equal(observation.outcome, 'not_applicable');
    assert.equal(observation.not_applicable_reason, 'cdn_edge_ip');
    assert.equal(observation.origin_lockdown_confirmed, false);
    assert.equal(observation.explicit_denial_observed, false);
  });

  it('a CDN address range alone marks the leg not applicable even without edge headers', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(403),
      baseline: { status_code: 200 },
      directAddress: '104.21.61.235',
    });
    assert.equal(observation.outcome, 'not_applicable');
    assert.match(observation.edge_signal, /address_range:cloudflare/);
  });

  it('a Cloudflare 403 for a mismatched Host behind SNI aistripped.com is not an origin observation', () => {
    const observation = classifyDirectOriginObservation({
      response: mockResponse(403, { server: 'cloudflare', 'cf-ray': '2' }),
      baseline: { status_code: 200 },
      directAddress: '198.51.100.7',
    });
    assert.equal(observation.outcome, 'not_applicable');
  });

  it('a TLS failure on the anycast address is a transport error excluded from verdicts', () => {
    const observation = classifyDirectOriginObservation({
      error: Object.assign(new Error('handshake'), { code: 'ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR' }),
      baseline: { status_code: 200 },
      directAddress: '104.21.61.235',
    });
    assert.equal(observation.outcome, 'transport_error');
    assert.equal(observation.origin_lockdown_confirmed, false);
  });
});

describe('PV-01 versions and labels agree', () => {
  it('affected check definitions are re-versioned so historical verdicts stay immutable', () => {
    for (const checkId of [
      'waf.fingerprint.safe',
      'waf.origin_bypass.safe',
      'origin.host_sni_bypass.safe',
      'origin.direct_reachability.safe',
      'origin.direct_bypass.safe',
    ]) {
      assert.notEqual(getCheckById(checkId).version, '1.0.0', checkId);
    }
  });

  it('classifier vocabulary is complete and portal labels match the backend', () => {
    assert.deepEqual([...EXTERNAL_OBSERVATION_OUTCOMES].sort(), Object.keys(EXTERNAL_OBSERVATION_LABELS).sort());
    assert.equal(classifyDirectOriginObservation({ attempted: false }).semantics_version, 'external-observation-v2');
    assert.equal(classifyDirectOriginObservation({ attempted: false }).outcome, 'not_tested');
    const portal = readFileSync(new URL('../../apps/web/react/src/lib/origin-observation.mjs', import.meta.url), 'utf8');
    for (const [outcome, label] of Object.entries(EXTERNAL_OBSERVATION_LABELS)) {
      assert.ok(portal.includes(`${outcome}: '${label}'`), `${outcome} label drifted`);
    }
  });
});
