// Fixture-only regressions for the 2026-10-06 aistripped.com staging defects (no live traffic).
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { targetKindCompatibilityError } from '../../src/contracts/checkTargetCompatibility.mjs';
import { portConnectTimeoutMs, probeOutsideInWafScan, probePortScanBounded } from '../../src/lib/capabilityProbes.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { assessWafEffectiveness } from '../../src/lib/edgeDetectionProjection.mjs';
import { parseNetworkEndpoint } from '../../src/lib/safeNetworkProbes.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { probeTcpConnect } from '../../workers/probe-worker.mjs';

const EDGE_V6 = '2606:4700:3036::6815:3deb';

function okResponse(status = 200, headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { status, headers: { get: (name) => lower[String(name).toLowerCase()] ?? null, forEach: (fn) => Object.entries(lower).forEach(([k, v]) => fn(v, k)) } };
}

describe('D1: IPv6 literal targets are bracketed in probe URLs', () => {
  it('runs the outside-in scan on an IPv6 IP target without throwing and dials the bracketed literal', async () => {
    const urls = [];
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      nonce_hash: 'sha256:v6',
      constraints: { max_requests: 2, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan', max_requests: 2 },
      target: { kind: 'ip', value: EDGE_V6 },
    }, {
      resolve4Fn: async () => [],
      resolve6Fn: async () => [],
      fetchFn: async (url) => {
        urls.push(String(url));
        return okResponse(200, { server: 'cloudflare', 'cf-ray': '1-LHR' });
      },
    });
    assert.ok(urls.length >= 1, JSON.stringify(outcome.metadata));
    assert.ok(urls.every((url) => url.startsWith(`https://[${EDGE_V6}]/`)), urls.join(','));
  });
});

describe('D2: an unbracketed IPv6 literal is never split into host and port', () => {
  it('parses bracketed, unbracketed, and host:port endpoints without changing the destination', () => {
    assert.equal(parseNetworkEndpoint({ target: { value: '2606:4700:4700::1:80' } }), null);
    assert.deepEqual(parseNetworkEndpoint({ target: { value: '2606:4700:4700::1:80', port: 443 } }), { host: '2606:4700:4700::1:80', port: 443 });
    assert.deepEqual(parseNetworkEndpoint({ target: { value: '[2001:db8::5]:8443' } }), { host: '2001:db8::5', port: 8443 });
    assert.deepEqual(parseNetworkEndpoint({ target: { value: '203.0.113.10:22' } }), { host: '203.0.113.10', port: 22 });
    assert.equal(parseNetworkEndpoint({ target: { value: '[203.0.113.10]:22' } }), null);
  });

  it('refuses to dial an undeclared address/port carved out of an IPv6 literal', async () => {
    const dialed = [];
    const outcome = await probeTcpConnect({
      target: { kind: 'ip', value: '2606:4700:4700::1:80' },
      constraints: { max_requests: 1, timeout_ms: 500 },
      probe_profile: { kind: 'tcp_connect', max_requests: 1 },
    }, { connectFn: (options) => { dialed.push(options); throw new Error('must not dial'); } });
    assert.equal(dialed.length, 0);
    assert.equal(outcome.external_result, 'error');
  });
});

describe('D5: forbidden-port and IPv6 reachability checks accept host:port targets', () => {
  const ids = ['l3.forbidden_tcp_port.safe', 'l3.forbidden_udp_port.safe', 'l3.ipv6_reachability.safe'];

  it('declares tcp (host:port) as a supported target kind', () => {
    for (const id of ids) {
      const check = CHECK_CATALOG.find((row) => row.check_id === id);
      assert.equal(targetKindCompatibilityError(check, { kind: 'tcp', value: '203.0.113.10:22' }), null, id);
    }
  });

  it('starts a run on a declared host:port target whose executor can derive the port', () => {
    freshStore();
    getStore().targets.push({ id: 'tgt_tcp', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'tcp', value: '[2001:db8::7]:22', created_at: new Date().toISOString() });
    const started = startTestRun({ tenantId: 'ten_demo', userId: 'u1', role: 'admin' }, { check_id: 'l3.forbidden_tcp_port.safe', target_group_id: 'tg_1', target_id: 'tgt_tcp' });
    assert.equal(started.error, undefined, JSON.stringify(started));
    assert.deepEqual(parseNetworkEndpoint({ target: { value: '[2001:db8::7]:22' } }), { host: '2001:db8::7', port: 22 });
  });
});

describe('D6: one filtered port no longer ends the bounded port scan', () => {
  it('splits the job deadline across the remaining ports', () => {
    assert.equal(portConnectTimeoutMs(5000, 3), 1650);
    assert.equal(portConnectTimeoutMs(20000, 1), 3000);
    assert.equal(portConnectTimeoutMs(40, 2), 0);
  });

  it('samples every declared port and keeps the open one when the others are silent', async () => {
    const probed = [];
    const outcome = await probePortScanBounded({
      constraints: { timeout_ms: 600, max_requests: 3 },
      target: { kind: 'ip', value: '10.0.0.5' },
      probe_profile: { kind: 'port_scan_bounded', max_requests: 3, ports: [443, 22, 3389] },
    }, {
      destinationPolicy: { allowPrivate: true },
      connectFn: ({ port }) => {
        probed.push(port);
        return {
          once(event, handler) {
            if (event === 'connect' && port === 443) setImmediate(handler);
          },
          end() {},
          destroy() {},
        };
      },
    });
    assert.deepEqual(probed, [443, 22, 3389]);
    assert.equal(outcome.external_result, 'connected');
    assert.deepEqual(outcome.metadata.open_ports, [443]);
    assert.deepEqual(outcome.metadata.filtered_ports, [22, 3389]);
    assert.ok(outcome.duration_ms <= 600, String(outcome.duration_ms));
  });

  it('runs the catalog scan with the 5 s job ceiling at version 1.1.0', () => {
    const check = CHECK_CATALOG.find((row) => row.check_id === 'l3.firewall_exposure_scan.safe');
    assert.equal(check.version, '1.1.0');
    assert.equal(check.probe_profile.timeout_ms, 5000);
  });
});

describe('D7: a completed TLS 1.3 handshake is a TLS profile observation, not an edge block', () => {
  it('never reports edge_protected or blocked-at-the-edge wording for a clean handshake', () => {
    const verdict = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeKind: 'tls_audit',
      probeIoObserved: true,
      probeMetadata: { tls_protocol: 'TLSv1.3', authorized: true, tls_issues: [] },
    });
    assert.equal(verdict.verdict, 'protected');
    assert.equal(verdict.createsFinding, false);
    assert.equal(/blocked at the edge/i.test(verdict.explanation), false);
  });

  it('reports profile issues as a TLS exposure', () => {
    const verdict = correlateExternalOnlyVerdict({
      externalResult: 'connected', expectedBehavior: 'must_block_before_origin', probeKind: 'tls_audit', probeIoObserved: true,
      probeMetadata: { tls_protocol: 'TLSv1', tls_issues: ['weak_tls_protocol'] },
    });
    assert.equal(verdict.verdict, 'exposed');
    assert.match(verdict.explanation, /weak_tls_protocol/);
  });
});

describe('D8: inconclusive marker rows never void definitive rows', () => {
  it('grades eight definitive allowed markers even with two inconclusive 405 POST rows', () => {
    const rows = [
      ...['sqli_marker', 'xss_marker', 'path_traversal_marker', 'combined_marker', 'sqli_case_marker', 'sqli_comment_marker', 'sqli_encoded_marker', 'xss_encoded_marker']
        .map((family) => ({ family, variant: 'plain', blocked: false, allowed: true })),
      { family: 'content_type_confusion', blocked: false, allowed: false, inconclusive: true, reason: 'unattributed_denial' },
      { family: 'multipart_confusion', blocked: false, allowed: false, inconclusive: true, reason: 'unattributed_denial' },
    ];
    const assessed = assessWafEffectiveness({ wafPresent: true, markerResults: rows });
    assert.equal(assessed.status, 'present_but_not_effective');
    assert.equal(assessed.tested_count, 8);
    assert.equal(assessed.inconclusive_count, 2);
  });
});

describe('D9: web service ports alone are not a firewall exposure', () => {
  const verdictFor = (openPorts) => correlateExternalOnlyVerdict({
    externalResult: 'connected', expectedBehavior: 'must_block_before_origin', probeKind: 'port_scan_bounded', probeIoObserved: true,
    probeMetadata: { open_ports: openPorts, filtered_ports: [22, 3389], closed_ports: [] },
  });

  it('records an open 443 as expected without a finding', () => {
    const verdict = verdictFor([443]);
    assert.equal(verdict.verdict, 'allowed_as_expected');
    assert.equal(verdict.createsFinding, false);
  });

  it('still raises an exposure when an admin port is open', () => {
    const verdict = verdictFor([443, 22]);
    assert.equal(verdict.verdict, 'edge_exposed');
    assert.equal(verdict.createsFinding, true);
  });
});
