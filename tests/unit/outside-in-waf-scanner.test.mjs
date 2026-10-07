import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  BENIGN_CLASS_MARKERS,
  EVASION_VARIANT_MARKERS,
  buildOutsideInPostureReport,
  buildOutsideInScanPlan,
  detectGenericWafPresence,
  isBlockedOrChallenged,
  resolveOutsideInDnsHints,
  resolveOutsideInTlsHints,
  readBoundedResponseBody,
  runOutsideInWafScan,
} from '../../src/lib/outsideInWafScanner.mjs';
import {
  executeCapabilityProbe,
  probeOutsideInWafScan,
} from '../../src/lib/capabilityProbes.mjs';

function rejectedTlsSocket() {
  const handlers = {};
  const socket = {
    once(event, handler) { handlers[event] = handler; },
    destroy() {},
  };
  queueMicrotask(() => handlers.error?.(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })));
  return socket;
}

function mockResponse(status, headers = {}) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const bytes = new TextEncoder().encode(normalized.__body ?? '');
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
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
    async text() {
      throw new Error('scanner must use bounded streaming reads');
    },
  };
}

  it('streams at most the configured response-body byte cap', async () => {
    let cancelled = false;
    let textCalled = false;
    const response = {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(9_000).fill(65));
        },
        cancel() {
          cancelled = true;
        },
      }),
      async text() {
        textCalled = true;
        throw new Error('unbounded text read');
      },
    };

    const body = await readBoundedResponseBody(response, 64);
    assert.equal(Buffer.byteLength(body, 'utf8'), 64);
    assert.equal(body, 'A'.repeat(64));
    assert.equal(cancelled, true);
    assert.equal(textCalled, false);
  });

describe('outside-in WAF scanner', () => {
  it('provider detection uses one ordinary HTTP request and up to three CNAME operations', () => {
    const check = getCheckById('waf.fingerprint.safe');
    assert.equal(check.probe_profile.kind, 'waf_fingerprint_observation');
    assert.equal(check.probe_profile.max_requests, 4);
    assert.equal(check.probe_profile.timeout_ms, 5000);
    assert.equal(check.probe_profile.follow_redirects, false);
  });

  it('resolveOutsideInDnsHints builds a single CNAME/A chain string', async () => {
    const hints = await resolveOutsideInDnsHints('shop.example.test', {
      resolveCname: async () => ['edge.cdn.cloudflare.net.'],
      resolve4: async () => ['198.51.100.10'],
    });
    assert.equal(hints.dns_chain, 'shop.example.test edge.cdn.cloudflare.net 198.51.100.10');
  });

  it('resolveOutsideInTlsHints reads protocol and cipher without HTTP budget', async () => {
    const hints = await resolveOutsideInTlsHints('https://edge.example.test/', {
      timeoutMs: 500,
      tlsConnect: (options) => {
        const handlers = {};
        const socket = {
          destroyed: false,
          destroy() { this.destroyed = true; },
          once(event, fn) { handlers[event] = fn; },
          getProtocol: () => 'TLSv1.3',
          getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }),
        };
        queueMicrotask(() => handlers.secureConnect?.());
        return socket;
      },
    });
    assert.equal(hints.tls_protocol_hint, 'TLSv1.3');
    assert.equal(hints.tls_cipher_hint, 'TLS_AES_128_GCM_SHA256');
  });

  it('follow_redirects follows up to two baseline redirects and fingerprints final host DNS', async () => {
    const baseUrl = 'https://shop.example.test/';
    const fetchCalls = [];
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      hostname: 'shop.example.test',
      budget: 6,
      timeoutMs: 1000,
      followRedirects: true,
      collectNetworkHints: true,
      resolveCname: async (host) => {
        if (host === 'edge.cdn.cloudflare.net') return [];
        return ['edge.cdn.cloudflare.net'];
      },
      resolve4: async () => ['198.51.100.10'],
      tlsConnect: (options) => {
        const handlers = {};
        const socket = {
          destroy() {},
          once(event, fn) { handlers[event] = fn; },
          getProtocol: () => 'TLSv1.3',
          getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }),
        };
        queueMicrotask(() => handlers.secureConnect?.());
        return socket;
      },
      fetchFn: async (url, init) => {
        fetchCalls.push(url);
        if (url === baseUrl) {
          return mockResponse(302, { location: 'https://edge.cdn.cloudflare.net/' });
        }
        if (url === 'https://edge.cdn.cloudflare.net/') {
          return mockResponse(200, {
            server: 'cloudflare',
            'cf-ray': 'redirected',
            'set-cookie': '__cf_bm=1; Path=/',
          });
        }
        return mockResponse(403, {
          server: 'cloudflare',
          'cf-ray': 'blocked',
          'cf-mitigated': 'challenge',
          __body: 'Cloudflare',
        });
      },
    });

    assert.equal(outcome.redirect_hops, 1);
    assert.equal(outcome.final_url_hostname, 'edge.cdn.cloudflare.net');
    assert.ok(outcome.dns_chain_hint.includes('edge.cdn.cloudflare.net'));
    assert.equal(outcome.tls_protocol_hint, 'TLSv1.3');
    assert.equal(outcome.tls_cipher_hint, 'TLS_AES_128_GCM_SHA256');
    assert.ok(outcome.vendor_chain_hints.length > 0);
    assert.equal(outcome.detected_vendor, 'cloudflare');
    assert.equal(fetchCalls[0], baseUrl);
    assert.equal(fetchCalls[1], 'https://edge.cdn.cloudflare.net/');
    assert.equal(outcome.requests_sent, 6);
    assert.equal(fetchCalls.length, outcome.requests_sent);
    assert.ok(fetchCalls.length <= 6);
  });

  it('omits network hints and does not follow redirects unless both are explicitly enabled', async () => {
    const calls = { fetch: 0, cname: 0, address: 0, tls: 0 };
    const outcome = await runOutsideInWafScan({
      url: 'https://shop.example.test/',
      budget: 1,
      timeoutMs: 1000,
      resolveCname: async () => { calls.cname += 1; return ['edge.example.test']; },
      resolve4: async () => { calls.address += 1; return ['198.51.100.10']; },
      tlsConnect: () => { calls.tls += 1; throw new Error('must not connect'); },
      fetchFn: async () => {
        calls.fetch += 1;
        return mockResponse(302, { location: 'https://redirect.example.test/' });
      },
    });

    assert.deepEqual(calls, { fetch: 1, cname: 0, address: 0, tls: 0 });
    assert.equal(outcome.network_hints_collected, false);
    assert.equal(outcome.redirect_following_enabled, false);
    assert.equal(Object.hasOwn(outcome, 'dns_chain_hint'), false);
    assert.equal(Object.hasOwn(outcome, 'tls_protocol_hint'), false);
    assert.equal(Object.hasOwn(outcome, 'vendor_chain_hints'), false);
  });

  it('buildOutsideInScanPlan preserves class markers before evasion phases within budget', () => {
    const plan = buildOutsideInScanPlan(6, { hasDirectIp: false });
    assert.deepEqual(plan.map((entry) => entry.phase), [
      'baseline',
      'combined_marker',
      'path_traversal_marker',
      'sqli_marker',
      'xss_marker',
      'content_type_confusion',
    ]);
    assert.deepEqual(
      ['sqli_marker', 'xss_marker', 'path_traversal_marker'].filter(
        (phase) => !plan.some((entry) => entry.phase === phase),
      ),
      [],
    );
    assert.equal(plan.some((entry) => entry.phase === 'no_user_agent'), false);
    assert.equal(plan.some((entry) => entry.phase === 'sqli_encoded_marker'), false);
    assert.equal(plan.some((entry) => entry.phase === 'sqli_case_marker'), false);

    const fullPlan = buildOutsideInScanPlan(13, { hasDirectIp: true });
    assert.equal(fullPlan.length, 13);
    for (const phase of ['xss_marker', 'xss_encoded_marker', 'no_user_agent', 'origin_bypass']) {
      assert.ok(fullPlan.some((entry) => entry.phase === phase), phase);
    }
  });

  it('keeps all three class markers in the combined request with unique parameter names', async () => {
    const urls = [];
    await runOutsideInWafScan({
      url: 'https://combined.example.test/',
      budget: 5,
      timeoutMs: 1000,
      fetchFn: async (requestUrl) => {
        urls.push(String(requestUrl));
        return mockResponse(200, { server: 'nginx' });
      },
    });
    const combined = new URL(urls[1]);
    assert.equal(combined.searchParams.size, 3);
    assert.deepEqual(
      new Set(combined.searchParams.values()),
      new Set(Object.values(BENIGN_CLASS_MARKERS)),
    );
  });

  it('does not infer a WAF from generic status drift alone', () => {
    const baseline = {
      status_code: 200,
      server_header: 'nginx',
      header_names: ['server'],
      connection_dropped: false,
    };
    const attack = {
      status_code: 403,
      server_header: 'nginx',
      header_names: ['server'],
      connection_dropped: false,
    };
    const result = detectGenericWafPresence({ baseline, attack, noUserAgent: baseline });
    assert.equal(result.detected, false);
    assert.ok(result.reasons.includes('status_code_drift'));

    const challenged = detectGenericWafPresence({
      baseline,
      attack: { ...attack, header_names: ['server', 'x-waf-block'] },
      noUserAgent: baseline,
    });
    assert.equal(challenged.detected, true);
    assert.equal(challenged.reason, 'waf_challenge_header');
  });

  it('treats an unhealthy 403/429 baseline and transport failures as inconclusive', () => {
    const empty = { blocked: false, challenged: false, allowed: false, inconclusive: true, block_suspected: false, denial_signature: null };
    for (const status_code of [403, 429]) {
      const baseline = {
        status_code,
        header_names: ['server'],
        server_header: 'nginx',
        connection_dropped: false,
      };
      assert.deepEqual(isBlockedOrChallenged({ ...baseline }, baseline), { ...empty, reason: 'baseline_unhealthy' });
    }
    assert.deepEqual(isBlockedOrChallenged({
      status_code: 0,
      connection_dropped: true,
      error_class: 'AbortError',
    }), { ...empty, reason: 'rst_or_drop_unattributed', error_class: 'AbortError' });
  });

  it('does not classify generic differential origin 403/429 responses as a WAF', async () => {
    for (const status of [403, 429]) {
      const baseUrl = `https://origin-${status}.example.test/`;
      const outcome = await runOutsideInWafScan({
        url: baseUrl,
        budget: 5,
        timeoutMs: 1000,
        fetchFn: async (requestUrl, init) => {
          const baseline = requestUrl === baseUrl
            && init?.method === 'GET'
            && init?.headers?.['User-Agent'];
          return baseline
            ? mockResponse(200, { server: 'nginx' })
            : mockResponse(status, { server: 'nginx', __body: 'generic origin rejection' });
        },
      });
      assert.equal(outcome.waf_detected, false, `status ${status}`);
      assert.equal(outcome.edge_signature.waf_present, false, `status ${status}`);
      assert.equal(outcome.block_page_signature_id, null, `status ${status}`);
      assert.equal(outcome.block_page_fingerprint_hash, null, `status ${status}`);
      assert.notEqual(outcome.waf_effectiveness.status, 'effective_for_tested_probes', `status ${status}`);
      assert.equal(outcome.waf_effectiveness.blocked_count ?? 0, 0, `status ${status}`);
      const sqli = outcome.marker_probes.find((row) => row.family === 'sqli_marker');
      assert.equal(sqli.blocked, false, `status ${status}`);
      assert.equal(sqli.block_suspected, true, `status ${status}`);
      assert.equal(sqli.reason, 'unattributed_denial', `status ${status}`);
      assert.notEqual(outcome.posture_status, 'protected', `status ${status}`);
    }
  });

  it('fingerprints Cloudflare but stays edge_protected without origin-lockdown evidence', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 13,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
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

    assert.equal(outcome.waf_detected, true);
    assert.equal(outcome.detected_vendor, 'cloudflare');
    assert.equal(outcome.posture_label, 'Edge protected · origin lockdown unverified');
    assert.equal(outcome.posture_status, 'edge_protected');
    assert.equal(outcome.probe_validation_passed, true);
    assert.equal(outcome.validation_passed, false);
    assert.equal(outcome.coverage_complete, true);
    assert.ok(outcome.marker_probes.some((probe) => probe.family === 'sqli_encoded_marker'));
  });

  it('reports Protected only when external origin-lockdown evidence is present', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 13,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'shop.example.test',
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        if (!isBaseline) {
          return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
        }
        return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
      },
      declaredOriginLockdown: { status_code: 403, header: { name: 'x-origin-lockdown', value: 'cdn-only' } },
      originBypassFn: async () => ({ res: mockResponse(403, { server: 'origin-nginx', 'x-origin-lockdown': 'cdn-only' }), error: null }),
    });
    assert.equal(outcome.posture_label, 'Protected');
    assert.equal(outcome.validation_passed, true);
    assert.equal(outcome.origin_lockdown_confirmed, true);
    assert.equal(outcome.origin_observation.outcome, 'explicit_denial_observed');
    assert.equal(outcome.origin_observation.denial_signature.kind, 'declared');
    assert.equal(outcome.network_firewall.direct_origin_reachability.status, 'denied');
    assert.equal(outcome.coverage_complete, true);
  });

  it('never reports Protected from an undeclared direct-origin 401 or 403', async () => {
    const baseUrl = 'https://shop.example.test/';
    for (const [status, reason, directStatus] of [[401, 'authentication_challenge', 'exposed'], [403, 'unattributed_denial', 'inconclusive']]) {
      const outcome = await runOutsideInWafScan({
        url: baseUrl,
        budget: 13,
        timeoutMs: 1000,
        directIp: '198.51.100.7',
        hostname: 'shop.example.test',
        fetchFn: async (url, init) => {
          const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
          return isBaseline
            ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
            : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
        },
        originBypassFn: async () => ({ res: mockResponse(status, { server: 'origin-nginx' }), error: null }),
      });
      assert.equal(outcome.origin_observation.outcome, 'response_observed', String(status));
      assert.equal(outcome.origin_observation.response_reason, reason);
      assert.equal(outcome.origin_lockdown_confirmed, false);
      assert.equal(outcome.posture_label, 'Edge protected · origin lockdown unverified');
      assert.equal(outcome.network_firewall.direct_origin_reachability.status, directStatus);
    }
  });

  it('never reports Protected when the direct-origin leg is refused or silent', async () => {
    const baseUrl = 'https://shop.example.test/';
    for (const error of [
      Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }),
      Object.assign(new Error('timed out'), { name: 'AbortError' }),
    ]) {
      const outcome = await runOutsideInWafScan({
        url: baseUrl,
        budget: 13,
        timeoutMs: 1000,
        directIp: '198.51.100.7',
        hostname: 'shop.example.test',
        fetchFn: async (url, init) => {
          const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
          return isBaseline
            ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
            : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
        },
        originBypassFn: async () => ({ res: null, error }),
      });
      assert.equal(outcome.posture_label, 'Edge protected · origin lockdown unverified');
      assert.equal(outcome.origin_lockdown_confirmed, false);
      assert.equal(outcome.direct_origin_reachable, false);
      assert.equal(outcome.network_firewall.status, 'inconclusive');
      assert.equal(outcome.coverage_complete, true);
    }
  });

  it('reports protected class evidence while optional phase coverage is incomplete', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 6,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        return isBaseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
    });

    assert.equal(outcome.coverage_complete, false);
    assert.ok(outcome.phases_dropped.includes('no_user_agent'));
    assert.equal(outcome.posture_label, 'Edge protected · origin lockdown unverified');
    assert.deepEqual(outcome.class_posture, {
      sqli: 'protected',
      xss: 'protected',
      path_traversal: 'protected',
    });
  });

  it('leaves an unrun class unknown and never reports the scan protected', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 3,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        return isBaseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
    });

    assert.equal(outcome.coverage_complete, false);
    assert.equal(outcome.class_posture.xss, 'unknown');
    assert.equal(outcome.probe_validation_passed, false);
    assert.equal(outcome.posture_label, 'Unknown');
    assert.equal(outcome.external_result, 'not_run');
  });

  it('flags evasion bypass when plain markers blocked but encoded allowed', async () => {
    const baseUrl = 'https://edge.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'];
        if (isBaseline) return mockResponse(200, { server: 'nginx' });
        if (url.includes('%25') || url.includes(EVASION_VARIANT_MARKERS.sqli_encoded)) {
          return mockResponse(200, { server: 'nginx' });
        }
        if (init?.method === 'POST') return mockResponse(200, { server: 'nginx' });
        return mockResponse(403, { server: 'nginx', 'x-waf-block': '1', __body: 'blocked' });
      },
    });
    assert.equal(outcome.evasion_bypass_suspected, true);
    assert.equal(outcome.posture_label, 'Underprotected');
    assert.equal(outcome.validation_failed, true);
  });

  it('runs content-type and multipart confusion POST probes within scan plan', async () => {
    const methods = [];
    const contentTypes = [];
    const outcome = await runOutsideInWafScan({
      url: 'https://api.example.test/',
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (requestUrl, init) => {
        methods.push(init?.method ?? 'GET');
        contentTypes.push(init?.headers?.['Content-Type'] ?? null);
        const baseline = requestUrl === 'https://api.example.test/'
          && init?.method === 'GET'
          && init?.headers?.['User-Agent'];
        return baseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': 'baseline' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': 'blocked', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
    });
    assert.ok(methods.includes('POST'));
    const contentTypeProbe = outcome.marker_probes.find((probe) => probe.family === 'content_type_confusion');
    assert.ok(contentTypeProbe);
    assert.equal(contentTypeProbe.blocked, true);
    const multipartProbe = outcome.marker_probes.find((probe) => probe.family === 'multipart_confusion');
    assert.ok(multipartProbe);
    assert.equal(multipartProbe.blocked, true);
    assert.ok(contentTypes.some((value) => String(value).includes('multipart/form-data')));
  });

  it('flags content-type confusion gap when POST marker is allowed through', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://api.example.test/',
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (requestUrl, init) => {
        if (init?.method === 'POST') return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
        const baseline = requestUrl === 'https://api.example.test/'
          && init?.headers?.['User-Agent'];
        return baseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
    });
    assert.equal(outcome.evasion_bypass_suspected, true);
    assert.ok(outcome.marker_probes.find((probe) => probe.family === 'content_type_confusion')?.allowed);
  });

  it('reports a detected WAF that passes every marker as present but not effective', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://monitor-only.example.test/',
      budget: 8,
      timeoutMs: 1000,
      fetchFn: async () => mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' }),
    });

    assert.equal(outcome.waf_detected, true);
    assert.equal(outcome.waf_effectiveness.status, 'present_but_not_effective');
    assert.equal(outcome.waf_effectiveness.percentage, 0);
    assert.equal(outcome.posture_status, 'underprotected');
    assert.notEqual(outcome.posture_label, 'Protected');
  });

  it('keeps no-WAF effectiveness unscored and handles a zero denominator', () => {
    const noWaf = buildOutsideInPostureReport({
      wafDetected: false,
      markerResults: [{ family: 'sqli_marker', variant: 'plain', allowed: true, blocked: false }],
    });
    assert.equal(noWaf.waf_effectiveness.status, 'no_waf_detected');
    assert.equal(noWaf.waf_effectiveness.percentage, null);

    const noMarkers = buildOutsideInPostureReport({ wafDetected: true, markerResults: [] });
    assert.equal(noMarkers.waf_effectiveness.status, 'inconclusive');
    assert.equal(noMarkers.waf_effectiveness.tested_count, 0);
    assert.equal(noMarkers.waf_effectiveness.percentage, null);
  });

  it('reports observed effectiveness math without rounding or denominator errors', () => {
    const markerResults = Array.from({ length: 10 }, (_, index) => ({
      family: index === 0 ? 'sqli_marker' : `variant_${index}`,
      variant: index === 0 ? 'plain' : `v${index}`,
      blocked: index < 9,
      allowed: index === 9,
    }));
    const report = buildOutsideInPostureReport({ wafDetected: true, markerResults });
    assert.equal(report.waf_effectiveness.status, 'partially_effective');
    assert.equal(report.waf_effectiveness.blocked_count, 9);
    assert.equal(report.waf_effectiveness.tested_count, 10);
    assert.equal(report.waf_effectiveness.percentage, 90);
  });

  it('returns timeout and inconclusive effectiveness instead of treating failures as blocks', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://timeout.example.test/',
      budget: 5,
      timeoutMs: 10,
      fetchFn: async () => {
        throw Object.assign(new Error('timed out'), { name: 'AbortError' });
      },
    });

    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.error_class, 'timeout');
    assert.equal(outcome.posture_status, 'inconclusive');
    assert.equal(outcome.waf_effectiveness.status, 'inconclusive');
    assert.equal(outcome.waf_effectiveness.blocked_count, 0);
    assert.equal(outcome.validation_passed, false);
  });

  it('does not turn a customer vendor hint into observed WAF detection', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://hint-only.example.test/',
      budget: 5,
      timeoutMs: 1000,
      customerVendorHint: 'cloudflare',
      fetchFn: async () => mockResponse(200, { server: 'nginx' }),
    });

    assert.equal(outcome.waf_detected, false);
    assert.equal(outcome.detected_vendor, null);
    assert.deepEqual(outcome.vendor_candidates, []);
  });

  it('reports underprotected when markers reach origin with 200', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://app.example.test/',
      budget: 8,
      timeoutMs: 1000,
      fetchFn: async () => mockResponse(200, { server: 'nginx' }),
    });

    assert.equal(outcome.waf_detected, false);
    assert.equal(outcome.posture_label, 'Underprotected');
    assert.equal(outcome.validation_failed, true);
  });

  it('does not confirm bypass from direct-origin reachability alone when the responder does not match the edge application signature', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://edge.example.test/',
      budget: 10,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: async (url, init) => {
        if (url === 'https://edge.example.test/' && init?.headers?.['User-Agent']) {
          return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
        }
        return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', __body: 'blocked' });
      },
      // A 200 from an unrelated nginx listener on the direct IP is network reachability, not
      // proof this is the protected application — the server header does not match the edge
      // baseline's ('cloudflare'), so this must not become a bypass finding.
      originBypassFn: async () => ({
        res: mockResponse(200, { server: 'origin-nginx' }),
        error: null,
      }),
    });

    assert.equal(outcome.direct_origin_reachable, true);
    assert.equal(outcome.origin_bypass_network_ingress_confirmed, true);
    assert.equal(outcome.origin_bypass_application_signature_match, false);
    assert.equal(outcome.origin_bypass_confirmed, false);
    assert.notEqual(outcome.posture_label, 'Bypass Risk');
  });

  it('treats a shared application Server header as supporting evidence only, never a confirmed bypass', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://edge.example.test/',
      budget: 10,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: async (url, init) => {
        if (url === 'https://edge.example.test/' && init?.headers?.['User-Agent']) {
          return mockResponse(200, { server: 'app-server-v2', 'cf-ray': '1' });
        }
        return mockResponse(403, { server: 'app-server-v2', 'cf-ray': '1', __body: 'blocked' });
      },
      originBypassFn: async () => ({
        res: mockResponse(200, { server: 'app-server-v2' }),
        error: null,
      }),
    });

    assert.equal(outcome.origin_bypass_application_signature_match, true);
    assert.equal(outcome.origin_bypass_confirmed, false);
    assert.equal(outcome.origin_bypass_suspected, true);
    assert.notEqual(outcome.posture_label, 'Bypass Risk');
    assert.equal(outcome.network_firewall.status, 'exposed');
  });

  it('reports an undeclared direct-origin 403 as reachable without lockdown, bypass, or exposure', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://edge.example.test/',
      budget: 13,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: async (requestUrl, init) => {
        const baseline = requestUrl === 'https://edge.example.test/'
          && init?.headers?.['User-Agent'];
        return baseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
      originBypassFn: async () => ({
        res: mockResponse(403, { server: 'origin-nginx' }),
        error: null,
      }),
    });

    assert.equal(outcome.direct_origin_reachable, true);
    assert.equal(outcome.origin_bypass_confirmed, false);
    assert.equal(outcome.network_firewall.status, 'inconclusive');
    assert.equal(outcome.network_firewall.direct_origin_reachability.explicit_denial_observed, false);
    assert.equal(outcome.network_firewall.direct_origin_reachability.response_reason, 'unattributed_denial');
    assert.equal(outcome.network_firewall.direct_origin_reachability.denial_signature, null);
    assert.equal(outcome.network_firewall.direct_origin_reachability.status_code, 403);
    assert.equal(outcome.network_firewall.port_exposure.status, 'not_tested');
  });

  it('probeOutsideInWafScan preserves timeout instead of promoting WAF presence to blocked', async () => {
    let calls = 0;
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      nonce_hash: 'sha256:timeout-proof',
      constraints: { max_requests: 13, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan', max_requests: 13 },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      fetchFn: async () => {
        calls += 1;
        if (calls === 1) return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
        throw Object.assign(new Error('timed out'), { name: 'AbortError' });
      },
    });

    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.external_result, 'timeout');
    assert.equal(outcome.metadata.error_class, 'timeout');
    assert.equal(outcome.metadata.posture_status, 'inconclusive');
    assert.equal(outcome.metadata.validation_passed, false);
    assert.equal(outcome.metadata.probe_validation_passed, false);
  });

  it('probeOutsideInWafScan reports edge_protected from external evidence with no origin lockdown', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      nonce_hash: 'sha256:edge-proof',
      constraints: { max_requests: 13, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan', max_requests: 13 },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      tlsConnect: rejectedTlsSocket,
      fetchFn: async (url, init) => {
        const isBaseline = url === 'https://edge.example.test/' && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        if (!isBaseline) {
          return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
        }
        return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
      },
    });

    assert.equal(outcome.metadata.origin_lockdown_confirmed, false);
    assert.equal(outcome.metadata.posture_label, 'Edge protected · origin lockdown unverified');
  });

  it('probeOutsideInWafScan preserves incomplete optional coverage with external-only evidence', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      nonce_hash: 'sha256:edge-proof',
      constraints: { max_requests: 6, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan', max_requests: 6 },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      tlsConnect: rejectedTlsSocket,
      fetchFn: async (url, init) => {
        const isBaseline = url === 'https://edge.example.test/' && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        return isBaseline
          ? mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' })
          : mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', 'cf-mitigated': 'challenge', __body: 'Cloudflare' });
      },
    });

    assert.equal(outcome.metadata.origin_lockdown_confirmed, false);
    assert.equal(outcome.metadata.posture_label, 'Edge protected · origin lockdown unverified');
    assert.equal(outcome.metadata.coverage_complete, false);
    assert.ok(outcome.metadata.phases_dropped.includes('no_user_agent'));
  });

  it('probeOutsideInWafScan integrates with capability probe dispatch', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      constraints: { max_requests: 10, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      tlsConnect: rejectedTlsSocket,
      fetchFn: async (url) => {
        const blocked = url.includes('OR') || url.includes('%');
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
      constraints: { max_requests: 8, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      tlsConnect: rejectedTlsSocket,
      fetchFn: async () => mockResponse(403, { server: 'akamai', 'x-akamai-request-id': '1', __body: 'Access Denied' }),
    });
    assert.equal(outcome.metadata.probe_kind, 'outside_in_waf_scan');
    assert.equal(outcome.metadata.detected_vendor, 'akamai');
  });

  it('buildOutsideInPostureReport maps validation failures to underprotected', () => {
    const report = buildOutsideInPostureReport({
      wafDetected: true,
      markerResults: [
        { family: 'sqli_marker', variant: 'plain', blocked: false, challenged: false, allowed: true },
      ],
      originBypassConfirmed: false,
    });
    assert.equal(report.posture_status, 'underprotected');
    assert.equal(report.posture_label, 'Underprotected');
    assert.equal(report.validation_failed, true);
  });

  it('exports benign and evasion marker constants', () => {
    assert.ok(BENIGN_CLASS_MARKERS.sqli.includes('OR'));
    assert.ok(EVASION_VARIANT_MARKERS.sqli_comment.includes('/**/'));
  });
});

describe('outside-in WAF scanner false-positive guards', () => {
  // Ordinary marketing-page markup that previously matched bare /f5/, /azure/, /prisma/ and
  // "security policy" block-page patterns and turned a WAF-less site into "F5 BIG-IP ASM".
  const ordinaryPage = '<html><head><style>body{background:#f5f5f5;color:#1f5f8b}</style></head>'
    + '<body><h1>Acme</h1><p>Deployed on Azure with Prisma ORM.</p>'
    + '<footer><a href="/security-policy">Security policy</a></footer></body></html>';

  it('does not fingerprint a WAF from an ordinary page and reports markers as reaching the origin', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://plain.example.test/',
      hostname: 'plain.example.test',
      budget: 13,
      timeoutMs: 2000,
      fetchFn: async (url) => {
        const path = new URL(url).pathname;
        return path === '/'
          ? mockResponse(200, { server: 'Caddy', 'content-type': 'text/html', __body: ordinaryPage })
          : mockResponse(404, { server: 'Caddy', 'content-type': 'text/plain', __body: 'not found' });
      },
    });
    assert.equal(outcome.block_page_signature_id, null);
    assert.equal(outcome.waf_detected, false);
    assert.equal(outcome.detected_vendor, null);
    const plainSqli = outcome.marker_probes.find((row) => row.family === 'sqli_marker');
    assert.equal(plainSqli.allowed, true);
    // An application 404 on a marker path is routing, not a WAF block.
    const traversal = outcome.marker_probes.find((row) => row.family === 'path_traversal_marker');
    assert.equal(traversal.blocked, false);
    assert.equal(traversal.inconclusive, true);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.waf_effectiveness.blocked_count, 0);
  });

  it('still recognizes a real F5 ASM block page', () => {
    const baseline = { status_code: 200, header_names: ['server'], server_header: 'BigIP' };
    const blocked = {
      status_code: 200,
      header_names: ['server'],
      server_header: 'BigIP',
      block_page_signature_id: 'block_sig_f5_asm_v1',
    };
    assert.equal(isBlockedOrChallenged(blocked, baseline).blocked, true);
  });

  it('treats an unsigned status change, even with a rewritten Server header, as block_suspected only', () => {
    const baseline = { status_code: 200, header_names: ['server'], server_header: 'nginx' };
    const snapshot = { status_code: 406, header_names: ['server'], server_header: 'edge-waf' };
    assert.equal(isBlockedOrChallenged(snapshot, baseline).blocked, false);
    assert.equal(isBlockedOrChallenged(snapshot, baseline).block_suspected, true);
    const appError = { status_code: 404, header_names: ['server'], server_header: 'nginx' };
    assert.deepEqual(
      { blocked: isBlockedOrChallenged(appError, baseline).blocked, inconclusive: isBlockedOrChallenged(appError, baseline).inconclusive },
      { blocked: false, inconclusive: true },
    );
  });
});

describe('benign-marker grading needs a control-specific signature', () => {
  const baseline = { status_code: 200, header_names: ['server'], server_header: 'nginx', denial_signature: null };
  const snap = (status_code, extra = {}) => ({ status_code, header_names: ['server'], server_header: 'nginx', denial_signature: null, ...extra });

  it('maps unsigned statuses to the research decision table', () => {
    const cases = [
      [200, { allowed: true, reason: null }],
      [302, { allowed: true, reason: null }],
      [401, { inconclusive: true, reason: 'authentication_gate_precedes_inspection' }],
      [403, { inconclusive: true, block_suspected: true, reason: 'unattributed_denial' }],
      [404, { inconclusive: true, block_suspected: true, reason: 'unattributed_denial' }],
      [406, { inconclusive: true, block_suspected: true, reason: 'unattributed_denial' }],
      [407, { inconclusive: true, reason: 'probe_path_error' }],
      [421, { inconclusive: true, reason: 'misdirected_request' }],
      [503, { inconclusive: true, reason: 'error_not_attributable' }],
    ];
    for (const [status, expected] of cases) {
      const graded = isBlockedOrChallenged(snap(status), baseline);
      assert.equal(graded.blocked, false, String(status));
      for (const [key, value] of Object.entries(expected)) assert.equal(graded[key], value, `${status} ${key}`);
    }
  });

  it('blocks on a vendor signature at any status, including F5 with 200', () => {
    const f5 = isBlockedOrChallenged(snap(200, { denial_signature: { kind: 'vendor', id: 'f5_asm_rejection', vendor: 'f5' } }), baseline);
    assert.equal(f5.blocked, true);
    assert.equal(f5.waf_product_hint, 'f5');
    assert.deepEqual(f5.denial_signature, { kind: 'vendor', id: 'f5_asm_rejection', vendor: 'f5' });
    const namesOnly = { status_code: 403, header_names: ['server', 'cf-mitigated'], server_header: 'nginx' };
    const challenge = isBlockedOrChallenged(namesOnly, baseline);
    assert.equal(challenge.blocked, true);
    assert.equal(challenge.challenged, true);
    assert.equal(isBlockedOrChallenged({ ...namesOnly, denial_signature: null }, baseline).blocked, false);
  });

  it('never grades against a baseline that is unhealthy or itself carries a block signature', () => {
    for (const bad of [{ ...baseline, status_code: 403 }, { ...baseline, header_names: ['server', 'cf-mitigated'] }, { ...baseline, denial_signature: { kind: 'vendor', id: 'cloudflare_challenge', vendor: 'cloudflare' } }]) {
      const graded = isBlockedOrChallenged(snap(403, { denial_signature: { kind: 'vendor', id: 'cloudflare_challenge', vendor: 'cloudflare' } }), bad);
      assert.equal(graded.blocked, false);
      assert.equal(graded.reason, 'baseline_unhealthy');
    }
  });

  it('records a matched customer-declared block response on the marker row', async () => {
    const baseUrl = 'https://declared.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 5,
      timeoutMs: 1000,
      declaredBlockSignature: { status_code: 406, header: { name: 'x-block-id', value: 'marker' } },
      fetchFn: async (url, init) => (url === baseUrl && init?.headers?.['User-Agent']
        ? mockResponse(200, { server: 'nginx' })
        : mockResponse(406, { server: 'nginx', 'x-block-id': 'marker' })),
    });
    const sqli = outcome.marker_probes.find((row) => row.family === 'sqli_marker');
    assert.equal(sqli.blocked, true);
    assert.equal(sqli.denial_signature.kind, 'declared');
  });

  it('aistripped.com fixture: XSS and SQLi markers answered 200 without cf-mitigated are not blocked', async () => {
    const baseUrl = 'https://aistripped.com/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 5,
      timeoutMs: 1000,
      fetchFn: async () => mockResponse(200, { server: 'cloudflare', 'cf-ray': 'synthetic', __body: '<html><div id="root"></div></html>' }),
    });
    for (const family of ['sqli_marker', 'xss_marker']) {
      const row = outcome.marker_probes.find((entry) => entry.family === family);
      assert.equal(row.allowed, true, family);
      assert.equal(row.blocked, false, family);
    }
    assert.equal(outcome.class_posture.sqli, 'underprotected');
    assert.notEqual(outcome.posture_status, 'protected');
  });
});
