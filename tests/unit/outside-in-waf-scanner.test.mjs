import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  BENIGN_CLASS_MARKERS,
  buildOutsideInPostureReport,
  detectGenericWafPresence,
  runOutsideInWafScan,
} from '../../src/lib/outsideInWafScanner.mjs';
import {
  executeCapabilityProbe,
  probeOutsideInWafScan,
} from '../../src/lib/capabilityProbes.mjs';

function mockResponse(status, headers = {}) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    status,
    headers: {
      get: (name) => normalized[String(name).toLowerCase()] ?? null,
      forEach: (fn) => {
        for (const [name, value] of Object.entries(normalized)) {
          fn(value, name);
        }
      },
    },
    async text() {
      return normalized.__body ?? '';
    },
  };
}

describe('outside-in WAF scanner', () => {
  it('waf.fingerprint.safe maps to outside_in_waf_scan probe profile', () => {
    const check = getCheckById('waf.fingerprint.safe');
    assert.equal(check.probe_profile.kind, 'outside_in_waf_scan');
    assert.equal(check.probe_profile.max_requests, 5);
  });

  it('detects generic WAF via status drift between baseline and marker probe', () => {
    const baseline = { status_code: 200, server_header: 'nginx', connection_dropped: false };
    const attack = { status_code: 403, server_header: 'nginx', connection_dropped: false };
    const result = detectGenericWafPresence({ baseline, attack, noUserAgent: baseline });
    assert.equal(result.detected, true);
    assert.ok(result.reasons.includes('status_code_drift'));
  });

  it('fingerprints Cloudflare and reports protected when markers are blocked', async () => {
    const calls = [];
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 7,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        calls.push(url);
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'];
        if (!isBaseline) {
          return mockResponse(403, {
            server: 'cloudflare',
            'cf-ray': 'abc123',
            'set-cookie': '__cf_bm=1; Path=/',
            __body: 'Attention Required! | Cloudflare',
          });
        }
        return mockResponse(200, {
          server: 'cloudflare',
          'cf-ray': 'abc123',
          'set-cookie': '__cf_bm=1; Path=/',
        });
      },
    });

    assert.ok(calls.length >= 5);
    assert.equal(outcome.waf_detected, true);
    assert.equal(outcome.detected_vendor, 'cloudflare');
    assert.equal(outcome.posture_label, 'Protected');
    assert.equal(outcome.validation_passed, true);
    assert.ok(outcome.marker_probes.every((probe) => probe.blocked));
  });

  it('reports underprotected when markers reach origin with 200', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://app.example.test/',
      budget: 7,
      timeoutMs: 1000,
      fetchFn: async () => mockResponse(200, { server: 'nginx' }),
    });

    assert.equal(outcome.waf_detected, false);
    assert.equal(outcome.posture_label, 'Underprotected');
    assert.equal(outcome.validation_failed, true);
    assert.ok(outcome.marker_probes.every((probe) => probe.allowed));
  });

  it('reports bypass risk when declared origin is reachable', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://edge.example.test/',
      budget: 8,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: async (url) => {
        if (url.includes(BENIGN_CLASS_MARKERS.sqli) || url.includes('astranull')) {
          return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', __body: 'blocked by cloudflare' });
        }
        return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
      },
      originBypassFn: async () => ({
        res: mockResponse(200, { server: 'origin-nginx' }),
        error: null,
      }),
    });

    assert.equal(outcome.origin_bypass_confirmed, true);
    assert.equal(outcome.posture_label, 'Bypass Risk');
    assert.equal(outcome.posture_status, 'underprotected');
  });

  it('probeOutsideInWafScan integrates with capability probe dispatch', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      constraints: { max_requests: 7, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      fetchFn: async (url) => {
        const blocked = url.includes('OR');
        return mockResponse(blocked ? 403 : 200, {
          server: 'cloudflare',
          'cf-ray': 'xyz',
          __body: blocked ? 'Cloudflare block page' : '',
        });
      },
    });

    assert.equal(outcome.metadata.probe_kind, 'outside_in_waf_scan');
    assert.equal(outcome.metadata.waf_fingerprint_detected, true);
    assert.ok(outcome.requests_sent >= 5);
    assert.ok(outcome.metadata.waf_fingerprint_catalog_version);
  });

  it('executeCapabilityProbe routes outside_in_waf_scan kind', async () => {
    const outcome = await executeCapabilityProbe({
      constraints: { max_requests: 6, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      fetchFn: async () => mockResponse(403, { server: 'akamai', 'x-akamai-request-id': '1', __body: 'Access Denied' }),
    });
    assert.equal(outcome.metadata.probe_kind, 'outside_in_waf_scan');
    assert.equal(outcome.metadata.detected_vendor, 'akamai');
  });

  it('buildOutsideInPostureReport maps validation failures to underprotected', () => {
    const report = buildOutsideInPostureReport({
      wafDetected: true,
      markerResults: [
        { family: 'sqli_marker', blocked: false, challenged: false, allowed: true },
      ],
      originBypassConfirmed: false,
    });
    assert.equal(report.posture_status, 'underprotected');
    assert.equal(report.posture_label, 'Underprotected');
    assert.equal(report.validation_failed, true);
  });
});