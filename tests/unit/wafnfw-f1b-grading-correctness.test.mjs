import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { additionalInputRefusal, checkRequiresAdditionalInput, getCheckById, CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { CUSTOM_CANARY_ONLY_REASON, catalogRuleCoverage, checkCatalogAssurance } from '../../src/contracts/ruleCoverage.mjs';
import { normalizeFirewallExpectation } from '../../src/contracts/protectionValidation.mjs';
import { classifyMarkerResponse, probeAxfrLeak, probePortScanBounded, probeRateLimitCanary } from '../../src/lib/capabilityProbes.mjs';
import { buildAxfrDnsMessage, frameDnsTcpMessage } from '../../src/lib/dnsTcpWire.mjs';
import {
  matchSuspectedVendorSignature,
  matchVendorDenialSignature,
} from '../../src/lib/externalObservationOutcomes.mjs';
import {
  FIREWALL_DENIAL_BASES,
  classifyFirewallChangeItem,
  classifyFirewallSample,
  firewallSampleFromProbeEvent,
} from '../../src/lib/firewallChangeAcceptance.mjs';
import {
  classifyTcpErrno,
  classifyUdpErrno,
  declaredDenyPorts,
  familyParity,
  portScanParity,
  resolveDeclaredNetworkPort,
} from '../../src/lib/networkProbeOutcomes.mjs';
import { enforcementFromGraded, postureFromEnforcement } from '../../src/lib/vectorProbes/wafProbeSupport.mjs';
import { runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { runRateLimitCanaryProbe } from '../../src/lib/vectorProbes/rateLimitCanaryProbes.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { buildTargetRuleCoverage } from '../../src/services/ruleCoverage.mjs';
import { createValidationPlan, executeValidationPlan } from '../../src/services/wafOrchestrator.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

function headers(map = {}) {
  const lower = Object.fromEntries(Object.entries(map).map(([k, v]) => [String(k).toLowerCase(), v]));
  return {
    get: (name) => lower[String(name).toLowerCase()] ?? null,
    forEach: (fn) => Object.entries(lower).forEach(([name, value]) => fn(value, name)),
  };
}

function res(status, hdrs = {}, body = '') {
  return { status, headers: headers(hdrs), bodyText: body, body_complete: true };
}

function markerish(url, init) {
  return String(url).includes('astranull') || Boolean(init?.headers?.['x-astranull-marker']);
}

function correlate(probeKind, probeMetadata, extra = {}) {
  return correlateExternalOnlyVerdict({
    probeKind,
    externalResult: extra.externalResult ?? 'connected',
    expectedBehavior: extra.expectedBehavior ?? 'must_block_before_origin',
    probeIoObserved: true,
    probeMetadata,
    declarations: extra.declarations ?? null,
    originBinding: extra.originBinding ?? null,
  });
}

const VERIFIER_GENERIC_CASES = Object.freeze([
  { status: 403, hdrs: { 'x-azure-ref': '20261013T000000Z-abc' }, body: '', vendor: 'azure' },
  { status: 403, hdrs: { via: '1.1 google' }, body: '<title>403</title>403 Forbidden', vendor: 'google' },
  { status: 406, hdrs: { 'x-served-by': 'cache-lhr7300-LHR' }, body: '', vendor: 'fastly' },
]);

describe('D2 unverified vendor signatures never grade blocked on generic proxy headers', () => {
  it('reproduces the three verifier cases as suspected blocks, not blocks', () => {
    for (const row of VERIFIER_GENERIC_CASES) {
      const response = res(row.status, row.hdrs, row.body);
      assert.equal(matchVendorDenialSignature({ statusCode: row.status, headers: response, bodyText: row.body }), null, row.vendor);
      const suspected = matchSuspectedVendorSignature({ statusCode: row.status, headers: response, bodyText: row.body });
      assert.equal(suspected.vendor, row.vendor);
      assert.equal(suspected.live_verified, false);
      const graded = classifyMarkerResponse(response, { bodyText: row.body });
      assert.equal(graded.blocked, false, row.vendor);
      assert.equal(graded.inconclusive, true, row.vendor);
      assert.equal(graded.reason, 'block_suspected_unverified_signature');
      assert.equal(graded.matched_vendor, row.vendor);
    }
  });

  it('grades every placement inconclusive with the matched vendor end to end', async () => {
    for (const row of VERIFIER_GENERIC_CASES) {
      const result = await runWafClassMarkerProbe({
        url: 'https://target.example/',
        marker_class: 'sqli',
        rng: () => 0,
        fetchFn: async (url, init) => (markerish(url, init) ? res(row.status, row.hdrs, row.body) : res(200, {}, 'ok')),
      });
      assert.notEqual(result.posture, 'protected', row.vendor);
      assert.equal(result.posture, 'inconclusive', row.vendor);
      assert.equal(result.enforcement, 'unknown');
      assert.equal(result.inconclusive_reason, 'block_suspected_unverified_signature');
      assert.equal(result.matched_vendor, row.vendor);
      assert.ok(result.placements.length > 0);
      for (const placement of result.placements) {
        assert.equal(placement.outcome, 'inconclusive');
        assert.equal(placement.inconclusive_reason, 'block_suspected_unverified_signature');
        assert.equal(placement.matched_vendor, row.vendor);
      }
      const verdict = correlate('waf_class_marker_probe', result, { externalResult: 'not_run' });
      assert.equal(verdict.verdict, 'inconclusive');
      assert.match(verdict.explanation, new RegExp(`Suspected vendor: ${row.vendor}`));
    }
  });

  it('a customer-declared block signature still grades blocked', async () => {
    const result = await runWafClassMarkerProbe({
      url: 'https://target.example/',
      marker_class: 'sqli',
      declared_block_signature: { header_name: 'x-block-ref', header_value: 'edge-policy', status_codes: [403] },
      fetchFn: async (url, init) => (markerish(url, init)
        ? res(403, { 'x-azure-ref': 'abc', 'x-block-ref': 'edge-policy' })
        : res(200, {}, 'ok')),
    });
    assert.equal(result.enforcement, 'enforced');
    assert.equal(result.posture, 'protected');
    assert.ok(result.placements.every((row) => row.outcome === 'blocked'));
  });
});

describe('D3 connection-limit exclusions run before the exposure branch', () => {
  const declarations = { version: 1, connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 3 }] };
  it('a CDN peer is inconclusive even above the declared limit', () => {
    const verdict = correlate('connection_limit_probe', { port: 443, accepted_count: 9, declared_limit: 3, peer_is_cdn: true }, { declarations });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /CDN edge/);
  });
  it('disagreeing samples are inconclusive even above the declared limit', () => {
    const verdict = correlate('connection_limit_probe', { port: 443, accepted_count: 9, declared_limit: 3, sample_agreement: 'disagree' }, { declarations });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /disagreed/);
  });
  it('still exposes from a non-CDN peer with agreeing samples', () => {
    assert.equal(correlate('connection_limit_probe', { port: 443, accepted_count: 9, declared_limit: 3 }, { declarations }).verdict, 'exposed');
  });
});

describe('D5 deny-check port resolution picks declared deny rules only', () => {
  const policy = [
    { protocol: 'tcp', port: 443, action: 'allow' },
    { protocol: 'tcp', port: 22, action: 'deny' },
    { protocol: 'udp', port: 161, action: 'deny' },
    { protocol: 'tcp', port: 3389, action: 'deny' },
  ];
  const job = (checkId, rows = policy) => ({ check_id: checkId, probe_profile: { declarations: { network_policy: rows } }, target: { kind: 'fqdn', value: 'a.example' } });

  it('reproduces the verifier case: [allow 443, deny 22] resolves 22 for a deny check', () => {
    assert.equal(resolveDeclaredNetworkPort(job('nfw.declared_deny_tcp.safe'), { protocol: 'tcp' }), 22);
    assert.equal(resolveDeclaredNetworkPort(job('l3.basic_deny_rule.safe'), { protocol: 'tcp' }), 22);
    assert.equal(resolveDeclaredNetworkPort(job('nfw.declared_deny_udp.safe'), { protocol: 'udp' }), 161);
  });
  it('never falls back to an allow rule and iterates deny rules within the budget', () => {
    assert.equal(resolveDeclaredNetworkPort(job('nfw.declared_deny_tcp.safe', [{ protocol: 'tcp', port: 443, action: 'allow' }]), { protocol: 'tcp' }), null);
    assert.deepEqual(declaredDenyPorts(job('nfw.declared_deny_tcp.safe'), { protocol: 'tcp' }), [22, 3389]);
    assert.deepEqual(declaredDenyPorts(job('nfw.declared_deny_tcp.safe'), { protocol: 'tcp', limit: 1 }), [22]);
    assert.equal(resolveDeclaredNetworkPort(job('l3.forbidden_tcp_port.safe'), { protocol: 'tcp' }), 22);
  });
});

describe('D6 challenged legs never count as not enforced', () => {
  const blocked = { blocked: true };
  const challenged = { challenged: true };
  const allowed = { allowed: true };
  it('block_or_challenge: a challenged leg satisfies the action', () => {
    assert.equal(enforcementFromGraded([blocked, challenged], { expectedAction: 'block_or_challenge' }), 'enforced');
    assert.equal(enforcementFromGraded([challenged, allowed], { expectedAction: 'block_or_challenge' }), 'partial');
  });
  it('block: mixed blocked and challenged is challenged, never exposed', () => {
    const enforcement = enforcementFromGraded([blocked, challenged], { expectedAction: 'block' });
    assert.equal(enforcement, 'challenged');
    assert.notEqual(postureFromEnforcement(enforcement).posture, 'exposed');
    assert.equal(enforcementFromGraded([challenged, challenged]), 'challenged');
  });
  it('correlation never exposes a partial record whose placements were only blocked and challenged', () => {
    const verdict = correlate('waf_class_marker_probe', {
      enforcement: 'partial',
      assurance_scope: 'managed_rule_marker',
      placements: [{ placement: 'query', outcome: 'blocked' }, { placement: 'path', outcome: 'challenged' }],
    });
    assert.equal(verdict.verdict, 'inconclusive');
  });
});

function refusedAxfrFrame(zone, transactionId = 0x4242) {
  const dns = buildAxfrDnsMessage(zone, { transactionId });
  dns.writeUInt16BE(0x8005, 2);
  return frameDnsTcpMessage(dns);
}

function nonRefusedAxfrFrame(zone, transactionId = 0x4242) {
  const dns = buildAxfrDnsMessage(zone, { transactionId });
  dns.writeUInt16BE(0x8400, 2);
  return frameDnsTcpMessage(dns);
}

function axfrSocket(framed) {
  return {
    once(event, handler) { if (event === 'connect') setImmediate(handler); },
    on(event, handler) { if (event === 'data') setImmediate(() => handler(framed)); },
    write() {},
    destroy() {},
  };
}

function axfrJob(maxRequests) {
  return {
    constraints: { timeout_ms: 1000, max_requests: maxRequests },
    probe_profile: { kind: 'dns_axfr_leak', max_requests: maxRequests },
    target: { kind: 'fqdn', value: 'example.test' },
  };
}

const NS_ADDRESSES = Object.freeze({ 'ns1.example.test': '203.0.113.53', 'ns2.example.test': '198.51.100.53', 'ns3.example.test': '192.0.2.53' });

describe('D7 AXFR derives its result across every nameserver', () => {
  it('does not report blocked when the first NS refuses and a later NS answers', async () => {
    let n = 0;
    const outcome = await probeAxfrLeak(axfrJob(4), {
      axfrTransactionId: 0x4242,
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test'],
      resolve4Fn: async (host) => [NS_ADDRESSES[host]],
      resolve6Fn: async () => [],
      connectFn: () => {
        n += 1;
        return axfrSocket(n === 1 ? refusedAxfrFrame('example.test') : nonRefusedAxfrFrame('example.test'));
      },
    });
    assert.equal(outcome.metadata.enforcement, 'not_enforced');
    assert.notEqual(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, false);
  });

  it('is partial, not enforced, when the budget leaves a nameserver unqueried', async () => {
    const outcome = await probeAxfrLeak(axfrJob(3), {
      axfrTransactionId: 0x4242,
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test', 'ns3.example.test'],
      resolve4Fn: async (host) => [NS_ADDRESSES[host]],
      resolve6Fn: async () => [],
      connectFn: () => axfrSocket(refusedAxfrFrame('example.test')),
    });
    assert.equal(outcome.metadata.enforcement, 'partial');
    assert.deepEqual(outcome.metadata.unqueried_nameservers, ['ns3.example.test']);
    assert.notEqual(outcome.external_result, 'blocked');
    const verdict = correlate('dns_axfr_leak', outcome.metadata, { externalResult: 'blocked' });
    assert.equal(verdict.verdict, 'inconclusive');
  });

  it('correlation: protected only when enforced, exposed on any leak, otherwise inconclusive', () => {
    assert.equal(correlate('dns_axfr_leak', { enforcement: 'enforced' }, { externalResult: 'blocked' }).verdict, 'inconclusive');
    assert.equal(correlate('dns_axfr_leak', { enforcement: 'unknown' }, { externalResult: 'blocked' }).verdict, 'inconclusive');
    assert.equal(correlate('dns_axfr_leak', {}, { externalResult: 'blocked' }).verdict, 'inconclusive');
    const leak = correlate('dns_axfr_leak', {
      enforcement: 'not_enforced',
      nameserver_results: [{ nameserver: 'ns1', queried: true, axfr_refused: true }, { nameserver: 'ns2', queried: true, axfr_leak: true }],
    }, { externalResult: 'connected' });
    assert.equal(leak.verdict, 'exposed');
    assert.equal(leak.createsFinding, true);
  });
});

describe('D8 rate-limit canary threshold semantics', () => {
  const meta = (fields) => ({ ...fields });
  const decl = (threshold = 5, window_seconds = 10) => ({ waf: { rate_limit_canary: { threshold, window_seconds } } });
  it('limited at request 1 is inconclusive (route may always be blocked)', () => {
    const verdict = correlate('rate_limit_canary_probe', meta({ requests_sent: 1, first_limited_at: 1, limited_outcome: 'blocked' }), { externalResult: 'blocked', declarations: decl(5, 10) });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /limited_before_threshold/);
  });
  it('threshold 5 with only 2 requests sent and never limited is inconclusive, not exposed', () => {
    const verdict = correlate('rate_limit_canary_probe', meta({ requests_sent: 2, first_limited_at: null, limited_outcome: null }), { declarations: decl(5, 10) });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /window_expired_before_threshold/);
  });
  it('protected at threshold+1 or threshold+2 after threshold allowed requests; exposed when never limited past threshold', () => {
    assert.equal(correlate('rate_limit_canary_probe', meta({ requests_sent: 6, first_limited_at: 6, allowed_before_limit: 5, limited_outcome: 'rate_limited' }), { externalResult: 'blocked', declarations: decl(5, 10) }).verdict, 'protected');
    assert.equal(correlate('rate_limit_canary_probe', meta({ requests_sent: 7, first_limited_at: 7, allowed_before_limit: 6, limited_outcome: 'rate_limited' }), { externalResult: 'blocked', declarations: decl(5, 10) }).verdict, 'protected');
    assert.equal(correlate('rate_limit_canary_probe', meta({ requests_sent: 6, first_limited_at: 6, allowed_before_limit: 3, limited_outcome: 'rate_limited' }), { externalResult: 'blocked', declarations: decl(5, 10) }).verdict, 'inconclusive');
    const exposed = correlate('rate_limit_canary_probe', meta({ requests_sent: 7, first_limited_at: null, limited_outcome: null, allowed_before_limit: 7 }), { declarations: decl(5, 10) });
    assert.equal(exposed.verdict, 'exposed');
    assert.equal(exposed.severity, 'low');
  });
  it('keeps requests_sent and allowed_before_limit in delegated probe metadata', async () => {
    const outcome = await probeRateLimitCanary({
      constraints: { timeout_ms: 1000, max_requests: 8 },
      probe_profile: { kind: 'rate_limit_canary_probe', max_requests: 8, timeout_ms: 1000, rate_limit_canary: { path: '/rl', method: 'GET', threshold: 2, window_seconds: 10 } },
      target: { kind: 'url', value: 'https://edge.example.test/app' },
    }, {
      signedJobVerified: true,
      fetchFn: (() => { let n = 0; return async () => { n += 1; return res(n <= 2 ? 200 : 429); }; })(),
    });
    assert.equal(outcome.metadata.requests_sent, 3);
    assert.equal(outcome.metadata.first_limited_at, 3);
    assert.equal(outcome.metadata.allowed_before_limit, 2);
    assert.equal(correlate('rate_limit_canary_probe', outcome.metadata, { externalResult: outcome.external_result, declarations: decl(2, 10) }).verdict, 'protected');
  });
  it('raw probe counts allowed requests before the limit', async () => {
    const raw = await runRateLimitCanaryProbe({
      url: 'https://edge.example.test/',
      probe_profile: { rate_limit_canary: { path: '/rl', method: 'GET', threshold: 3, window_seconds: 10 } },
      fetchFn: async () => res(429),
    });
    assert.equal(raw.first_limited_at, 1);
    assert.equal(raw.allowed_before_limit, 0);
  });
});

function handshakeSocket() {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.end = () => {};
  queueMicrotask(() => socket.emit('connect'));
  return socket;
}

function refusedSocket() {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.end = () => {};
  queueMicrotask(() => socket.emit('error', Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' })));
  return socket;
}

function dualStackScan(maxRequests, ports, connectFn) {
  return probePortScanBounded({
    constraints: { timeout_ms: 4000, max_requests: maxRequests },
    target: { kind: 'fqdn', value: 'dual.example.test' },
    probe_profile: { kind: 'port_scan_bounded', declared_ports: ports, address_family: 'both' },
  }, {
    resolve4Fn: async () => ['203.0.113.20'],
    resolve6Fn: async () => ['2001:db8::20'],
    connectFn,
  });
}

describe('D9 dual-stack port scan splits the budget across families', () => {
  it('round-robins per port so both families are sampled on the same port', async () => {
    const probed = [];
    const outcome = await dualStackScan(2, [22, 443], ({ host, port }) => {
      probed.push(`${host}:${port}`);
      return host.includes(':') ? refusedSocket() : handshakeSocket();
    });
    assert.deepEqual(probed, ['203.0.113.20:22', '2001:db8::20:22']);
    assert.deepEqual(outcome.metadata.families.ipv4.ports_sampled, [22]);
    assert.deepEqual(outcome.metadata.families.ipv6.ports_sampled, [22]);
    assert.equal(outcome.metadata.parity, 'mismatch');
    assert.deepEqual(outcome.metadata.parity_ports, [22]);
  });

  it('a family with zero probes is not_sampled and never a parity mismatch', async () => {
    const outcome = await dualStackScan(1, [22], ({ host }) => (host.includes(':') ? refusedSocket() : handshakeSocket()));
    assert.equal(outcome.metadata.families.ipv6.not_sampled, true);
    assert.equal(outcome.metadata.parity, 'single_family');
    assert.equal(outcome.metadata.parity_reason, 'family_not_sampled');
    assert.equal(familyParity({ ipv4: { tcp_outcome: 'handshake' }, ipv6: { tcp_outcome: 'refused_rst', not_sampled: true } }), 'single_family');
    assert.equal(portScanParity({ ipv4: { open_ports: [22], ports_sampled: [22] }, ipv6: { open_ports: [], ports_sampled: [] } }).parity, 'single_family');
  });

  it('correlation states IPv6 parity only when both families were sampled on the leaking port', () => {
    const declarations = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
    const unsampled = correlate('port_scan_bounded', {
      open_ports: [22],
      parity: 'mismatch',
      families: { ipv4: { open_ports: [22], ports_sampled: [22] }, ipv6: { open_ports: [], ports_sampled: [], not_sampled: true } },
    }, { declarations });
    assert.equal(unsampled.verdict, 'exposed');
    assert.doesNotMatch(unsampled.explanation, /parity/);
    const sampled = correlate('port_scan_bounded', {
      open_ports: [22],
      parity: 'mismatch',
      families: { ipv4: { open_ports: [22], ports_sampled: [22] }, ipv6: { open_ports: [], closed_ports: [22], ports_sampled: [22] } },
    }, { declarations });
    assert.match(sampled.explanation, /IPv6 parity mismatch/);
  });
});

describe('D10 catalog copy matches what correlation concludes', () => {
  it('method policy is verdict-capable, declaration-free and names TRACE plus a token method', () => {
    const check = getCheckById('waf.http_method_policy_enforced.safe');
    assert.match(check.description, /TRACE/);
    assert.match(check.description, /no request body/);
    assert.match(check.verdict_logic, /protected/);
    assert.match(check.verdict_logic, /exposed/);
    assert.match(check.verdict_logic, /inconclusive/);
    assert.doesNotMatch(`${check.description} ${check.verdict_logic} ${check.explanation_template}`, /declared-disallowed|No protection, exposure/i);
    assert.equal(check.version, '1.2.0');
  });
  it('forbidden TCP port and every runnable reflect./amp. reflector check are violation/exposure-only, never protected', () => {
    const forbidden = getCheckById('l3.forbidden_tcp_port.safe');
    assert.match(forbidden.verdict_logic, /Violation-only/);
    assert.match(forbidden.verdict_logic, /protected is never available/);
    const reflectors = CHECK_CATALOG.filter((check) => /^(reflect|amp)\./.test(check.check_id) && check.probe_profile?.kind === 'reflection_service_probe');
    assert.ok(reflectors.length >= 15);
    for (const check of reflectors) {
      assert.match(check.verdict_logic, /Exposure-only/, check.check_id);
      assert.match(check.verdict_logic, /protected is never available/, check.check_id);
      assert.doesNotMatch(check.description, /No protection, exposure or capacity conclusion/, check.check_id);
      assert.match(check.version, /^\d+\.[1-9]\d*\.0$/, check.check_id);
    }
  });
  it('origin lockdown states the binding is required and exposed needs application identity', () => {
    const check = getCheckById('nfw.origin_lockdown.safe');
    assert.match(check.description, /declared origin binding/);
    assert.match(check.verdict_logic, /application identity/);
    assert.match(check.verdict_logic, /TCP handshake alone/);
  });
  it('origin lockdown correlation needs both the binding and lockdown_expected', () => {
    const metadata = {
      peer_is_cdn: false,
      application_bypass_confirmed: true,
      origin_observation: { outcome: 'application_identity_confirmed', status_code: 200, application_bypass_confirmed: true },
    };
    const binding = { id: 'ob_1', status: 'active' };
    assert.equal(correlate('host_sni_bypass', metadata, { originBinding: binding }).verdict, 'inconclusive');
    assert.equal(correlate('host_sni_bypass', metadata, { declarations: { origin: { lockdown_expected: true } } }).verdict, 'inconclusive');
  });
});

const TENANT = 'ten_1';
const SOURCE = 'public-worker-eu';
let seq = 0;
function fwSample({ kind = 'tcp_connect', result = 'error', metadata = {}, target = 'tgt_ssh', day = '2026-10-03', minute = 0 } = {}) {
  seq += 1;
  const run = { id: `run_${seq}`, tenant_id: TENANT, target_id: target, check_id: kind === 'udp_probe' ? 'l3.forbidden_udp_port.safe' : 'l3.forbidden_tcp_port.safe', status: 'verdicted', check_version: '1.0.0' };
  const event = {
    id: `evt_${seq}`, tenant_id: TENANT, test_run_id: run.id, target_id: target, check_id: run.check_id,
    signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: `${day}T00:${String(minute).padStart(2, '0')}:00.000Z`,
    metadata: { profile_kind: kind, probe_kind: kind, external_result: result, probe_worker_id: 'worker_eu_1', safety_attestation: { requests_sent: 1, duration_ms: 5 }, ...metadata },
  };
  const targets = { tgt_ssh: { id: 'tgt_ssh', tenant_id: TENANT, value: 'fw.example.test:22' }, tgt_dns: { id: 'tgt_dns', tenant_id: TENANT, value: 'ns.example.test:53' } };
  return firewallSampleFromProbeEvent({ event, run, target: targets[target], verdictId: `verdict_${seq}`, sourcePerspective: SOURCE });
}

function fwExpectation(overrides = {}) {
  return {
    ...normalizeFirewallExpectation({
      destination_target_id: 'tgt_ssh', protocol: 'tcp', port: 22, expected: 'deny', source_perspective: SOURCE, change_id: 'CHG-1', ...overrides,
    }, { tenantId: TENANT }),
    id: 'fwx_1',
    status: 'active',
  };
}

function observation(exp, sample) {
  const verdict = classifyFirewallSample(exp, sample);
  return { evidence_id: sample.evidence_id, test_run_id: sample.test_run_id, observation_class: verdict.observation_class, source_perspective: SOURCE, worker_id: 'worker_eu_1', observed_at: sample.observed_at, ...(verdict.denial_basis ? { denial_basis: verdict.denial_basis } : {}) };
}

describe('D11 firewall denial bases are explicit remote filter evidence only', () => {
  it('maps EACCES/EPERM to local errors, never ICMP admin-prohibited', () => {
    for (const code of ['EACCES', 'EPERM']) {
      assert.deepEqual(classifyTcpErrno(code), { tcp_outcome: 'error', icmp: null, local_error: true });
      assert.deepEqual(classifyUdpErrno(code), { udp_outcome: 'error', icmp: null, local_error: true });
    }
    assert.equal(classifyTcpErrno('EHOSTUNREACH').tcp_outcome, 'rejected_icmp');
    assert.deepEqual([...FIREWALL_DENIAL_BASES], ['icmp_admin_prohibited', 'rejected_icmp']);
  });

  it('UDP port-unreachable is a closed port, not a deny', () => {
    const exp = fwExpectation({ protocol: 'udp', port: 53, destination_target_id: 'tgt_dns' });
    const one = fwSample({ kind: 'udp_probe', target: 'tgt_dns', metadata: { udp_outcome: 'port_unreachable' } });
    const classified = classifyFirewallSample(exp, one);
    assert.equal(classified.observation_class, 'transport_error');
    assert.equal(classified.denial_basis, 'port_unreachable');
    const pre = [1, 2].map((minute) => observation(exp, fwSample({ kind: 'udp_probe', target: 'tgt_dns', day: '2026-10-01', minute, metadata: { udp_outcome: 'port_unreachable' } })));
    const post = [1, 2].map((minute) => observation(exp, fwSample({ kind: 'udp_probe', target: 'tgt_dns', minute, metadata: { udp_outcome: 'port_unreachable' } })));
    const item = classifyFirewallChangeItem({ expectation: exp, baselineObservations: pre, candidateObservations: post, compatibility: { comparable: true, reasons: [] } });
    assert.equal(item.status, 'inconclusive');
    assert.ok(item.reasons.includes('closed_port_not_control_specific'));
    const legacy = post.map((row) => ({ ...row, observation_class: 'explicit_denial_observed' }));
    const reread = classifyFirewallChangeItem({ expectation: exp, baselineObservations: pre, candidateObservations: legacy, compatibility: { comparable: true, reasons: [] } });
    assert.equal(reread.status, 'inconclusive');
  });

  it('local socket refusals keep the item inconclusive with local_error', () => {
    const exp = fwExpectation();
    const pre = [1, 2].map((minute) => observation(exp, fwSample({ day: '2026-10-01', minute, result: 'connected', metadata: { tcp_outcome: 'handshake' } })));
    const post = [1, 2].map((minute) => observation(exp, fwSample({ minute, metadata: { tcp_outcome: 'error', local_error: true, error_class: 'EACCES' } })));
    assert.ok(post.every((row) => row.denial_basis === 'local_probe_error' && row.observation_class === 'transport_error'));
    const item = classifyFirewallChangeItem({ expectation: exp, baselineObservations: pre, candidateObservations: post, compatibility: { comparable: true, reasons: [] } });
    assert.equal(item.status, 'inconclusive');
    assert.equal(item.local_error, true);
    assert.ok(item.reasons.includes('local_probe_error'));
  });
});

describe('D12 reflector exposure is direct evidence, not a firewall violation', () => {
  it('exposes a validated reply without a declaration and labels the basis', () => {
    const verdict = correlate('reflection_service_probe', {
      protocol: 'udp', port: 123, udp_outcome: 'validated_reply', service_validated: true,
      protocol_results: [{ payload_profile: 'ntp_mode6_readvar', udp_outcome: 'validated_reply', service_validated: true }],
    });
    assert.equal(verdict.verdict, 'exposed');
    assert.equal(verdict.metadata.exposure_basis, 'validated_reflector_reply');
    assert.match(verdict.explanation, /^Open NTP reflector reachable from the internet/);
    assert.doesNotMatch(verdict.explanation, /violated/);
  });
  it('never exposes an unvalidated reply, and a declared deny keeps the deny wording', () => {
    assert.notEqual(correlate('reflection_service_probe', { protocol: 'udp', port: 123, udp_outcome: 'unvalidated_reply' }).verdict, 'exposed');
    const declared = correlate('reflection_service_probe', { protocol: 'udp', port: 123, udp_outcome: 'validated_reply', address_family: 4 }, {
      declarations: { version: 1, network_policy: [{ protocol: 'udp', port: 123, action: 'deny', address_family: 'any' }] },
    });
    assert.match(declared.explanation, /Declared deny for udp\/123/);
  });
  it('TCP deny checks still need a declared deny to expose', () => {
    assert.notEqual(correlate('tcp_connect', { protocol: 'tcp', port: 22, tcp_outcome: 'handshake', address_family: 4 }).verdict, 'exposed');
  });
});

describe('D14 rule coverage is honest about canaries and unrunnable checks', () => {
  const categories = Object.fromEntries(catalogRuleCoverage().categories.map((row) => [row.id, row]));
  it('unbound custom-canary categories are observations with an unavailable-setup reason', () => {
    for (const id of ['custom_canary', 'request_smuggling', 'ssrf_xxe_jndi', 'deserialization', 'file_upload', 'ssti']) {
      assert.equal(categories[id].assurance, 'observation', id);
      assert.equal(categories[id].assurance_reason, CUSTOM_CANARY_ONLY_REASON, id);
    }
    assert.match(CUSTOM_CANARY_ONLY_REASON, /setup is not available/i);
    assert.doesNotMatch(categories.custom_canary.description, /proves/i);
  });
  it('retains historical custom verdicts without counting them as current rule protection', () => {
    const nowMs = Date.parse('2026-10-15T12:00:00Z');
    const checkId = 'waf.request_smuggling_marker.safe';
    for (const verdict of ['protected', 'exposed']) {
      const recorded = { verdict, evidence_ids: ['ev_historical'] };
      const original = structuredClone(recorded);
      const result = buildTargetRuleCoverage({
        targetId: 'tgt_coverage', declarations: {}, nowMs, env: {},
        runs: [{ id: 'run_historical', check_id: checkId, started_at: '2026-10-15T11:00:00Z', completed_at: '2026-10-15T11:01:00Z' }],
        verdictForRun: () => recorded,
      });
      const category = result.categories.find((row) => row.id === 'request_smuggling');
      assert.equal(category.status, 'inconclusive');
      assert.equal(category.checks[0].status, 'inconclusive');
      assert.equal(category.checks[0].verdict, verdict);
      assert.deepEqual(recorded, original);
    }
  });
  it('a category whose only probe can never run is not_assessable with a reason', () => {
    assert.equal(categories.stateful_inspection.assurance, 'not_assessable');
    assert.match(categories.stateful_inspection.assurance_reason, /can never run/);
    assert.equal(checkCatalogAssurance(getCheckById('l3.tcp_flag_anomaly.readiness')), 'not_assessable');
  });
  it('unknown probe kinds default to observation, never verdict', () => {
    const unknown = { check_id: 'x.unknown.safe', safety_class: 'safe', probe_profile: { kind: 'brand_new_kind', max_requests: 1, timeout_ms: 1000 } };
    assert.equal(checkCatalogAssurance(unknown), 'observation');
  });
});

describe('D16 basic deny-rule runnability', () => {
  const check = getCheckById('l3.basic_deny_rule.safe');
  it('runs for a tcp host:port target or a declared TCP deny, refused otherwise', () => {
    assert.equal(additionalInputRefusal(check, {}, { target: { kind: 'tcp', value: '192.0.2.10:22' } }), null);
    assert.equal(additionalInputRefusal(check, {}, {
      target: { kind: 'fqdn', value: 'a.example', metadata: { control_declarations: { network_policy: [{ protocol: 'tcp', port: 22, action: 'deny' }] } } },
    }), null);
    const refused = additionalInputRefusal(check, {}, {
      target: { kind: 'fqdn', value: 'a.example', metadata: { control_declarations: { network_policy: [{ protocol: 'tcp', port: 443, action: 'allow' }] } } },
    });
    assert.equal(refused.error, 'port_or_declared_deny_required');
    assert.match(refused.message, /tcp host:port target/);
    assert.equal(additionalInputRefusal(check, {}).error, 'port_or_declared_deny_required');
    assert.equal(checkRequiresAdditionalInput(check), true);
    assert.ok(check.supported_targets.includes('tcp'));
    assert.equal(check.mechanism_supported, true);
  });
});

describe('D17 WAF orchestrator preflight refuses SOC-only scenarios', () => {
  const envSnapshot = { ...process.env };
  const ctx = { tenantId: 'ten_demo', userId: 'usr_demo', role: 'engineer' };
  beforeEach(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_PROBE_MODE = 'signed-worker';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = 'probe-worker-secret-at-least-32-chars!!';
    resetStoreForTests({
      tenants: [{ id: 'ten_demo', name: 'Demo' }],
      targetGroups: [{ id: 'tg_1', tenant_id: 'ten_demo', name: 'TG', expected_behavior_default: 'must_block_before_origin', ownership_status: 'dns_verified' }],
      targets: [{ id: 'tgt_1', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'app.example.com', expected_behavior: 'must_block_before_origin' }],
      wafAssets: [{ id: 'waf_1', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', canonical_url: 'https://app.example.com', status: 'protected', expected_waf_required: true }],
      wafValidationPlans: [],
      testRuns: [],
      probeJobs: [],
      auditLog: [],
    });
  });
  afterEach(() => {
    for (const key of Object.keys(process.env)) if (!(key in envSnapshot)) delete process.env[key];
    Object.assign(process.env, envSnapshot);
  });

  it('rce_marker is refused at preflight with a clear reason, before any run or probe job', () => {
    const created = createValidationPlan(ctx, { target_group_id: 'tg_1', scenarios: ['rce_marker'], max_concurrent: 2, timeout_ms: 45_000 });
    assert.equal(created.error, undefined);
    const executed = executeValidationPlan(ctx, created.validation_plan.id, loadRuntimeConfig());
    assert.equal(executed.error, 'soc_gated_check');
    assert.equal(executed.status, 403);
    assert.equal(executed.check_id, 'waf.offensive_rce.soc');
    assert.match(executed.message, /SOC-only check waf\.offensive_rce\.soc/);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().testRuns.length, 0);
    assert.ok(getStore().auditLog.some((row) => row.action === 'waf.validation_plan.blocked_soc_gated'));
  });
});
