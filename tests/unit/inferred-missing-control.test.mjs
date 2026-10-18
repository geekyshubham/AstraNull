import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';

function correlate(checkId, probeKind, probeMetadata, extra = {}) {
  return correlateExternalOnlyVerdict({
    checkId,
    probeKind,
    externalResult: extra.externalResult ?? 'connected',
    expectedBehavior: extra.expectedBehavior ?? 'must_block_before_origin',
    probeIoObserved: extra.probeIoObserved ?? true,
    probeMetadata,
    declarations: extra.declarations ?? null,
    originBinding: null,
  });
}

const gap = (result) => {
  assert.equal(result.verdict, 'exposed', result.explanation);
  assert.equal(result.createsFinding, true);
  assert.equal(result.confidence, 'external_only');
};
const inferred = (result) => {
  gap(result);
  assert.equal(result.inferred_without_declaration, true);
};
const noGap = (result) => {
  assert.notEqual(result.verdict, 'exposed', result.explanation);
  assert.notEqual(result.createsFinding, true);
};

const scan = (open, others = { closed_ports: [443] }, extra = {}) => ({
  open_ports: open, peer_is_cdn: false, sample_agreement: 'agree',
  families: { ipv4: { open_ports: open, closed_ports: [], rejected_ports: [], filtered_ports: [], ...others, ports_sampled: [...open, 443] } },
  ...extra,
});

describe('control missing vs control present without a customer declaration', () => {
  for (const checkId of ['nfw.management_port_exposure.safe', 'l3.firewall_exposure_scan.safe']) {
    describe(checkId, () => {
      it('control missing: a never-public service answers while other ports are closed', () => {
        const result = correlate(checkId, 'port_scan_bounded', scan([6379, 2375, 22]));
        inferred(result);
        assert.equal(result.severity, 'high');
        assert.match(result.explanation, /tcp\/6379 Redis \(ipv4\)/);
        assert.match(result.explanation, /tcp\/2375 Docker Engine API \(ipv4\)/);
        assert.doesNotMatch(result.explanation, /tcp\/22/);
      });
      it('control present: only possibly-intended public ports answer', () => noGap(correlate(checkId, 'port_scan_bounded', scan([22, 3389]))));
      it('control present: every never-public port is filtered', () => noGap(correlate(checkId, 'port_scan_bounded', scan([], { filtered_ports: [6379, 2375] }))));
      it('guard: an accept-all host is not treated as exposed', () => noGap(correlate(checkId, 'port_scan_bounded', scan([6379, 443], {}))));
      it('guard: a CDN peer is not treated as exposed', () => noGap(correlate(checkId, 'port_scan_bounded', scan([6379], undefined, { peer_is_cdn: true }))));
      it('guard: unattested probe I/O is not treated as exposed', () => noGap(correlate(checkId, 'port_scan_bounded', scan([6379]), { probeIoObserved: false })));
      it('guard: a CDN address family is skipped', () => {
        const metadata = scan([6379]);
        metadata.families.ipv4.peer_is_cdn = true;
        noGap(correlate(checkId, 'port_scan_bounded', metadata));
      });
      it('guard: disagreeing samples in a family are skipped', () => {
        const metadata = scan([6379]);
        metadata.families.ipv4.sample_agreement = 'disagree';
        noGap(correlate(checkId, 'port_scan_bounded', metadata));
      });
      it('guard: the only closed port being the open port itself is not a closed-port control', () => {
        noGap(correlate(checkId, 'port_scan_bounded', scan([6379], { closed_ports: [6379] })));
      });
      it('guard: a non-connected scan result is not upgraded', () => {
        noGap(correlate(checkId, 'port_scan_bounded', scan([6379]), { externalResult: 'blocked' }));
      });
    });
  }

  it('a different check sharing the port-scan kind keeps observation semantics', () => {
    noGap(correlate('l3.some_other_scan.safe', 'port_scan_bounded', scan([6379])));
  });

  it('declared-deny verdicts keep precedence over the inferred rule', () => {
    const result = correlate('nfw.management_port_exposure.safe', 'port_scan_bounded', scan([6379]), {
      declarations: { version: 1, network_policy: [{ protocol: 'tcp', port: 6379, action: 'deny', address_family: 'any' }] },
    });
    gap(result);
    assert.match(result.explanation, /^Declared deny for tcp\/6379/);
  });

  describe('reflect.redis_direct_exposure.safe', () => {
    const samples = (outcome) => [{ tcp_outcome: outcome, port: 6379 }, { tcp_outcome: outcome, port: 6379 }];
    it('control missing: two agreeing handshakes on 6379', () => {
      inferred(correlate('reflect.redis_direct_exposure.safe', 'tcp_connect', { tcp_outcome: 'handshake', port: 6379, samples: samples('handshake'), sample_agreement: 'agree', peer_is_cdn: false }));
    });
    it('control present: refused', () => {
      noGap(correlate('reflect.redis_direct_exposure.safe', 'tcp_connect', { tcp_outcome: 'refused_rst', port: 6379, samples: samples('refused_rst'), sample_agreement: 'agree', peer_is_cdn: false }, { externalResult: 'blocked' }));
    });
    it('guard: disagreeing samples', () => {
      noGap(correlate('reflect.redis_direct_exposure.safe', 'tcp_connect', { tcp_outcome: 'handshake', port: 6379, samples: [{ tcp_outcome: 'handshake', port: 6379 }, { tcp_outcome: 'timeout', port: 6379 }], sample_agreement: 'disagree', peer_is_cdn: false }));
    });
  });

  describe('tls.full_audit.safe', () => {
    it('control missing: expired certificate', () => {
      const result = correlate('tls.full_audit.safe', 'tls_audit', { complete: true, tls_issues: ['cert_expired'], days_to_expiry: -3, valid_to: 'Jan 1 00:00:00 2026 GMT' });
      inferred(result);
      assert.match(result.explanation, /expired 3 day\(s\) ago/);
    });
    it('control missing: not yet valid', () => inferred(correlate('tls.full_audit.safe', 'tls_audit', { complete: true, tls_issues: ['certificate_not_yet_valid'] })));
    it('control present: valid certificate', () => noGap(correlate('tls.full_audit.safe', 'tls_audit', { complete: true, tls_issues: [], days_to_expiry: 80 })));
    it('guard: hostname mismatch or private chain alone is not inferred', () => {
      noGap(correlate('tls.full_audit.safe', 'tls_audit', { complete: true, tls_issues: ['certificate_hostname_mismatch', 'unauthorized_chain'] }));
    });
    it('guard: incomplete handshake', () => noGap(correlate('tls.full_audit.safe', 'tls_audit', { complete: false, tls_issues: ['cert_expired'] })));
  });

  describe('dns.secondary_failover.safe', () => {
    it('control missing: one nameserver', () => {
      const result = correlate('dns.secondary_failover.safe', 'dns_failover_posture', { zone: 'example.test', nameserver_count: 1, nameservers: ['ns1.example.test'], nameserver_count_below_two: true });
      inferred(result);
      assert.match(result.explanation, /single nameserver \(ns1\.example\.test\)/);
    });
    it('control present: two nameservers', () => {
      noGap(correlate('dns.secondary_failover.safe', 'dns_failover_posture', { zone: 'example.test', nameserver_count: 2, nameserver_count_below_two: false }));
    });
    it('guard: zero nameservers is a lookup problem, not a gap', () => {
      noGap(correlate('dns.secondary_failover.safe', 'dns_failover_posture', { nameserver_count: 0, nameserver_count_below_two: true }));
    });
  });

  describe('l7.cors_posture.safe', () => {
    it('control missing: foreign origin reflected with credentials', () => {
      inferred(correlate('l7.cors_posture.safe', 'cors_posture_probe', { access_control_allow_origin: 'https://probe.invalid.astranull', credentials_advertised: true }));
    });
    it('control present: no CORS grant', () => noGap(correlate('l7.cors_posture.safe', 'cors_posture_probe', { access_control_allow_origin: null, credentials_advertised: false })));
    it('guard: wildcard with credentials is rejected by browsers', () => {
      noGap(correlate('l7.cors_posture.safe', 'cors_posture_probe', { access_control_allow_origin: '*', credentials_advertised: true }));
    });
    it('guard: reflected origin without credentials', () => {
      noGap(correlate('l7.cors_posture.safe', 'cors_posture_probe', { access_control_allow_origin: 'https://probe.invalid.astranull', credentials_advertised: false }));
    });
  });

  describe('protocol.grpc_reflection_stream.safe', () => {
    it('control missing: confirmed unauthenticated reflection', () => {
      inferred(correlate('protocol.grpc_reflection_stream.safe', 'grpc_reflection_probe', { reflection_service_exposed: true, protocol_identity_confirmed: true }));
    });
    it('control present: reflection not exposed', () => {
      noGap(correlate('protocol.grpc_reflection_stream.safe', 'grpc_reflection_probe', { reflection_service_exposed: false, protocol_identity_confirmed: true }));
    });
    it('guard: unconfirmed protocol identity', () => {
      noGap(correlate('protocol.grpc_reflection_stream.safe', 'grpc_reflection_probe', { reflection_service_exposed: true, protocol_identity_confirmed: false }));
    });
  });

  describe('protocol.http2_stream_concurrency.safe', () => {
    it('control missing: no stream limit advertised', () => {
      inferred(correlate('protocol.http2_stream_concurrency.safe', 'http2_settings', { max_concurrent_streams: 4294967295 }));
    });
    it('control present: a finite limit is advertised', () => {
      noGap(correlate('protocol.http2_stream_concurrency.safe', 'http2_settings', { max_concurrent_streams: 128 }));
    });
    it('guard: settings never observed', () => noGap(correlate('protocol.http2_stream_concurrency.safe', 'http2_settings', {})));
  });

  describe('tls.renegotiation.readiness', () => {
    const session = (extra) => ({ tls_protocol: 'TLSv1.2', client_renegotiation_attempted: true, client_renegotiation_accepted: true, ...extra });
    it('control missing: client renegotiation accepted on TLS 1.2', () => inferred(correlate('tls.renegotiation.readiness', 'tls_session', session())));
    it('control present: renegotiation refused', () => noGap(correlate('tls.renegotiation.readiness', 'tls_session', session({ client_renegotiation_accepted: false }))));
    it('control present: TLS 1.3 has no renegotiation', () => noGap(correlate('tls.renegotiation.readiness', 'tls_session', session({ tls_protocol: 'TLSv1.3', client_renegotiation_attempted: false }))));
    it('guard: no recorded attempt', () => noGap(correlate('tls.renegotiation.readiness', 'tls_session', { tls_protocol: 'TLSv1.2' })));
  });

  it('never infers a gap from a failed or timed-out probe', () => {
    for (const externalResult of ['timeout', 'error', 'not_run']) {
      noGap(correlate('l7.cors_posture.safe', 'cors_posture_probe', { access_control_allow_origin: 'https://probe.invalid.astranull', credentials_advertised: true }, { externalResult }));
    }
  });
});
