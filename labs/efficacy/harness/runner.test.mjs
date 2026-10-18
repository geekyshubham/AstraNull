import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseArgs,
  resolveTargetSpec,
  gradeResult,
  isSafetyRefused,
  validateManifest,
  validateNetworkName,
  validateAddress,
  validateHostname,
  normalizeVerdict,
  extractSafeProbeMetadata,
} from './runner.mjs';

test('validateNetworkName accepts allowed patterns and rejects unauthorized ones', () => {
  assert.equal(validateNetworkName('anl-dns-lab-net'), true);
  assert.equal(validateNetworkName('anl-nfw-ipv6-gap-net'), true);
  assert.equal(validateNetworkName('anl-harness-client'), true);
  assert.equal(validateNetworkName('anl-test-server'), true);
  assert.equal(validateNetworkName('public-network'), false);
  assert.equal(validateNetworkName('anl-invalid'), false);
  assert.equal(validateNetworkName(''), false);
});

test('validateAddress restricts to 172.31.0.0/16 and fd00:a57a:*', () => {
  assert.equal(validateAddress('172.31.41.10'), true);
  assert.equal(validateAddress('172.31.0.1'), true);
  assert.equal(validateAddress('172.31.255.254'), true);
  assert.equal(validateAddress('fd00:a57a:33::10'), true);
  assert.equal(validateAddress('fd00:a57a::1'), true);
  assert.equal(validateAddress('192.168.1.1'), false);
  assert.equal(validateAddress('10.0.0.1'), false);
  assert.equal(validateAddress('8.8.8.8'), false);
  assert.equal(validateAddress('2001:db8::1'), false);
});

test('validateHostname allows synthetic lab domains only', () => {
  assert.equal(validateHostname('lab.efficacy.invalid'), true);
  assert.equal(validateHostname('parity.lab.efficacy.invalid'), true);
  assert.equal(validateHostname('sub.parity.lab.efficacy.invalid'), true);
  assert.equal(validateHostname(null), true);
  assert.equal(validateHostname('example.com'), false);
  assert.equal(validateHostname('invalid.com'), false);
});

test('validateManifest validates compliant manifests and rejects invalid entries', () => {
  const validManifest = {
    networks: ['anl-dns-lab-net'],
    targets: [
      {
        name: 'test-target',
        address: '172.31.41.10',
        hostname: 'lab.efficacy.invalid',
      },
    ],
  };
  assert.equal(validateManifest(validManifest), true);

  assert.throws(() => validateManifest({ networks: ['bad-net'], targets: [{ address: '172.31.1.1' }] }));
  assert.throws(() => validateManifest({ networks: ['anl-test-net'], targets: [{ address: '8.8.8.8' }] }));
  assert.throws(() => validateManifest({ networks: ['anl-test-net'], targets: [{ address: '172.31.1.1', hostname: 'google.com' }] }));
  assert.throws(() => validateManifest({ networks: ['anl-test-net'], targets: [] }));
});

test('isSafetyRefused blocks destructive/volumetric checks and permits safe ones', () => {
  assert.equal(isSafetyRefused('l4.syn_flood.offensive', {}), true);
  assert.equal(isSafetyRefused('protocol.slowloris.offensive', {}), true);
  assert.equal(isSafetyRefused('udp.memcached_stats.amplification', {}), true);
  assert.equal(isSafetyRefused('safe.check', { kind: 'volumetric' }), true);
  assert.equal(isSafetyRefused('dns.secondary_failover.safe', { kind: 'dns_wire_query' }), false);
  assert.equal(isSafetyRefused('tls.full_audit.safe', { kind: 'tls_handshake' }), false);
});

test('resolveTargetSpec prioritizes fqdn/dns before ip when hostname is present', () => {
  const target = {
    name: 'test',
    address: '172.31.41.10',
    hostname: 'parity.lab.efficacy.invalid',
    ports: [{ port: 8080, protocol: 'tcp', service: 'http' }],
  };

  const dnsCheck = { supported_targets: ['fqdn', 'dns', 'ip'] };
  assert.deepEqual(resolveTargetSpec(target, dnsCheck), {
    kind: 'fqdn',
    value: 'parity.lab.efficacy.invalid',
  });

  const ipOnlyCheck = { supported_targets: ['ip'] };
  assert.deepEqual(resolveTargetSpec(target, ipOnlyCheck), {
    kind: 'ip',
    value: '172.31.41.10',
  });

  const urlCheck = { supported_targets: ['url'] };
  assert.deepEqual(resolveTargetSpec(target, urlCheck), {
    kind: 'url',
    value: 'http://parity.lab.efficacy.invalid:8080/',
  });

  const deniedTarget = { ...target, declarations: { network_policy: [{ protocol: 'tcp', port: 8080, action: 'deny' }] } };
  assert.deepEqual(resolveTargetSpec(deniedTarget, { supported_targets: ['ip', 'fqdn', 'tcp'] }), {
    kind: 'tcp',
    value: 'parity.lab.efficacy.invalid:8080',
  });

  const ipv6Target = {
    name: 'ipv6-target',
    address: 'fd00:a57a:33::10',
    hostname: null,
    ports: [{ port: 8080, protocol: 'tcp', service: 'http' }],
  };
  assert.deepEqual(resolveTargetSpec(ipv6Target, urlCheck), {
    kind: 'url',
    value: 'http://[fd00:a57a:33::10]:8080/',
  });
});

test('gradeResult classifies gaps, protections, skips, and execution errors accurately', () => {
  assert.equal(gradeResult('gap', 'gap', 'completed', 'verdicted'), 'detected gap');
  assert.equal(gradeResult('gap', 'protected', 'completed', 'verdicted'), 'missed gap');
  assert.equal(gradeResult('protected', 'protected', 'completed', 'verdicted'), 'correct protected');
  assert.equal(gradeResult('protected', 'gap', 'completed', 'verdicted'), 'false alarm');
  assert.equal(gradeResult('inconclusive_expected', 'inconclusive', 'completed', 'verdicted'), 'inconclusive');
  assert.equal(gradeResult('not_applicable', 'gap', 'not_applicable', 'skipped'), 'not_applicable');
  assert.equal(gradeResult('gap', 'skipped_safety', 'skipped_safety', 'skipped'), 'skipped_safety');
  assert.equal(gradeResult('gap', 'execution_error', 'dispatch_rejected', 'rejected'), 'execution_error');
  assert.equal(gradeResult('protected', 'inconclusive', 'timeout', 'timeout'), 'execution_error');
  assert.equal(gradeResult('protected', 'execution_error', 'failed', 'failed'), 'execution_error');
  assert.equal(gradeResult('gap', 'inconclusive', 'cancelled', 'cancelled'), 'execution_error');
});

test('extractSafeProbeMetadata omits raw bodies, headers, and secrets', () => {
  const rawMetadata = {
    status_code: 200,
    rtt_ms: 12,
    tls_version: 'TLSv1.3',
    raw_body: 'SECRET_PAYLOAD',
    request_headers: { Authorization: 'Bearer token' },
    api_key: 'top-secret',
  };
  const events = [
    { event_type: 'placement_observation', placement: 'edge-1' },
    { event_type: 'attestation_generated', attestation: true },
  ];
  const extracted = extractSafeProbeMetadata(rawMetadata, events);
  assert.equal(extracted.status_code, 200);
  assert.equal(extracted.rtt_ms, 12);
  assert.equal(extracted.tls_version, 'TLSv1.3');
  assert.equal(extracted.raw_body, undefined);
  assert.equal(extracted.request_headers, undefined);
  assert.equal(extracted.api_key, undefined);
  assert.equal(extracted.placement_observations, 1);
  assert.equal(extracted.attestation_count, 1);
});

test('parseArgs reads manifest, out, checks, and prefix', () => {
  const args = parseArgs(['--manifest', 'lab.json', '--out', '/tmp/out', '--checks', 'c1,c2', '--prefix', 'waf.']);
  assert.equal(args.manifest, 'lab.json');
  assert.equal(args.out, '/tmp/out');
  assert.deepEqual(args.checks, ['c1', 'c2']);
  assert.equal(args.prefix, 'waf.');
});

test('extractSafeProbeMetadata scrubs secrets and preserves primitive fields', () => {
  const ev = {
    signal_type: 'probe_result',
    metadata: {
      external_result: 'connected',
      tls_issues: ['cert_expired'],
      complete: true,
      placements: [{ placement: 'query', outcome: 'blocked', status_code: 403, raw_body: 'secret' }],
      safety_attestation: { requests_sent: 1, probe_requests_sent: 1, destination_resolver_attempts: 0, total_operations: 1, duration_ms: 5, nonce: 'nonce-val' },
      families: { ipv6: { tcp_outcome: 'handshake', samples: [{}], headers: { auth: 'secret' } } },
      raw_body: 'body-secret',
      nonce: 'nonce-secret',
    },
  };
  const meta = extractSafeProbeMetadata(null, [ev]);
  assert.equal(meta.external_result, 'connected');
  assert.deepEqual(meta.tls_issues, ['cert_expired']);
  assert.equal(meta.complete, true);
  assert.equal(meta.placements[0].placement, 'query');
  assert.equal(meta.placements[0].outcome, 'blocked');
  assert.equal(meta.placements[0].status_code, 403);
  assert.equal(meta.placements[0].raw_body, undefined);
  assert.equal(meta.safety_attestation.requests_sent, 1);
  assert.equal(meta.safety_attestation.duration_ms, 5);
  assert.equal(meta.safety_attestation.nonce, undefined);
  assert.equal(meta.families.ipv6.tcp_outcome, 'handshake');
  assert.equal(meta.families.ipv6.sample_count, 1);
  assert.equal(meta.families.ipv6.samples, undefined);
  assert.equal(meta.families.ipv6.headers, undefined);
  assert.equal(meta.raw_body, undefined);
  assert.equal(meta.nonce, undefined);

  const nonProbe = extractSafeProbeMetadata(null, [{ signal_type: 'lifecycle', metadata: { external_result: 'connected' } }]);
  assert.equal(nonProbe?.external_result, undefined);
});

