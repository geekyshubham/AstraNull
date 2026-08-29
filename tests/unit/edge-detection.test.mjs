import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  detectEdgeForHostname,
  normalizeDetectionHostname,
} from '../../src/lib/edgeDetection.mjs';
import { EDGE_SIGNATURE_CORPUS_VERSION } from '../../src/lib/edgeFingerprint.mjs';

function mockResponse(status, headers = {}) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    status,
    headers: {
      get: (name) => normalized[String(name).toLowerCase()] ?? null,
    },
    async text() {
      return normalized.__body ?? '';
    },
  };
}

/** Native-fetch-like headers: `get` is a receiver-bound prototype method, not a closure. */
class PrototypeHeaders {
  constructor(entries) {
    this.entries = entries;
  }

  get(name) {
    return this.entries[String(name).toLowerCase()] ?? null;
  }
}

function prototypeResponse(status, headers = {}) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    status,
    headers: new PrototypeHeaders(normalized),
    async text() {
      return normalized.__body ?? '';
    },
  };
}

function cloudflareFetch(requestLog = []) {
  return async (url, init) => {
    requestLog.push({ url, init });
    return mockResponse(200, {
      server: 'cloudflare',
      'cf-ray': '8a1b2c3d4e5f',
      'set-cookie': '__cfduid=abc; Path=/',
    });
  };
}

const CLOUDFLARE_DNS = {
  resolveCname: async () => ['edge.cdn.cloudflare.net'],
  resolve4: async () => ['108.138.5.5'],
  resolve6: async () => [],
};

describe('edge detection hostname normalization', () => {
  it('accepts bare hostnames and IP literals', () => {
    assert.deepEqual(normalizeDetectionHostname('Shop.Example.com.'), { hostname: 'shop.example.com' });
    assert.deepEqual(normalizeDetectionHostname('198.51.100.10'), { hostname: '198.51.100.10' });
    assert.deepEqual(normalizeDetectionHostname('[2001:db8::1]'), { hostname: '2001:db8::1' });
  });

  it('rejects URLs, credentials, paths, ports, and junk', () => {
    for (const bad of [
      'https://example.com',
      'example.com/path',
      'user:pass@example.com',
      'example.com:443',
      'example com',
      '',
      'not_a_hostname!!',
      '-leadingdash.example.com',
    ]) {
      assert.ok(normalizeDetectionHostname(bad).error, `expected rejection: ${bad}`);
    }
  });
});

describe('hostname → edge detection', () => {
  it('detects a Cloudflare WAF + CDN from one passive request and DNS metadata', async () => {
    const requestLog = [];
    const result = await detectEdgeForHostname({
      hostname: 'shop.example.test',
      fetchFn: cloudflareFetch(requestLog),
      ...CLOUDFLARE_DNS,
    });

    assert.equal(result.error, undefined);
    assert.equal(result.detection, 'host_edge_detection');
    assert.equal(result.tier, 'passive_only');
    assert.equal(result.corpus_version, EDGE_SIGNATURE_CORPUS_VERSION);
    assert.equal(result.waf_present, true);
    assert.equal(result.best_vendor.vendor, 'cloudflare');
    assert.deepEqual(result.address_matches, [{ family: 'cdn', provider: 'cloudfront' }]);
    assert.equal(result.cdn_detected, true);
    assert.equal(result.requests_sent, 1);
    assert.ok(result.dns_chain.includes('edge.cdn.cloudflare.net'));
    assert.ok(result.dns_chain.includes('108.138.5.5'));
  });

  it('handles native receiver-bound Headers.get (regression: unbound method)', async () => {
    const result = await detectEdgeForHostname({
      hostname: 'shop.example.test',
      fetchFn: async () => prototypeResponse(200, {
        server: 'cloudflare',
        'cf-ray': 'abc123',
      }),
      ...CLOUDFLARE_DNS,
    });
    assert.equal(result.waf_present, true, 'prototype-bound headers.get must still be readable');
    assert.equal(result.best_vendor?.vendor, 'cloudflare');
    assert.ok(result.best_vendor.confidence >= 0.65, 'both server and cf-ray signals should match');
  });

  it('sends exactly one benign GET with no redirects followed', async () => {
    const requestLog = [];
    await detectEdgeForHostname({
      hostname: 'shop.example.test',
      fetchFn: async (url, init) => {
        requestLog.push({ url, init });
        return mockResponse(302, { location: 'https://elsewhere.example.test/' });
      },
      ...CLOUDFLARE_DNS,
    });
    assert.equal(requestLog.length, 1);
    assert.ok(requestLog[0].url.startsWith('https://'));
    assert.equal(requestLog[0].init.redirect, 'manual');
  });

  it('classifies an IP-literal host by address ranges without DNS', async () => {
    const requestLog = [];
    const result = await detectEdgeForHostname({
      hostname: '108.138.5.5',
      fetchFn: cloudflareFetch(requestLog),
    });
    assert.deepEqual(result.address_matches, [{ family: 'cdn', provider: 'cloudfront' }]);
    assert.equal(result.cdn_detected, true);
    assert.deepEqual(result.resolved_ips, ['108.138.5.5']);
  });

  it('reports no edge for a plain origin host', async () => {
    const result = await detectEdgeForHostname({
      hostname: 'origin.internal.example.test',
      fetchFn: async () => mockResponse(200, { server: 'nginx/1.24.0' }),
      resolveCname: async () => { throw Object.assign(new Error('no data'), { code: 'ENODATA' }); },
      resolve4: async () => ['198.51.100.10'],
      resolve6: async () => { throw Object.assign(new Error('no data'), { code: 'ENODATA' }); },
    });
    assert.equal(result.waf_present, false);
    assert.equal(result.cdn_detected, false);
    assert.equal(result.best_vendor, null);
    assert.deepEqual(result.address_matches, []);
  });

  it('returns a request error class when the host is unreachable', async () => {
    const result = await detectEdgeForHostname({
      hostname: 'blackhole.example.test',
      fetchFn: async () => {
        throw Object.assign(new Error('connect refused'), { code: 'ECONNREFUSED' });
      },
      resolveCname: async () => [],
      resolve4: async () => ['198.51.100.10'],
      resolve6: async () => [],
    });
    assert.equal(result.request_error_class, 'ECONNREFUSED');
    assert.equal(result.waf_present, false);
    assert.equal(result.best_vendor, null);
  });

  it('caps timeout input and reports probe timeouts distinctly', async () => {
    const result = await detectEdgeForHostname({
      hostname: 'slow.example.test',
      timeoutMs: 999_999,
      fetchFn: async (_url, init) => {
        await new Promise((resolve) => {
          init.signal.addEventListener('abort', resolve, { once: true });
        });
        const err = new Error('This operation was aborted');
        err.name = 'AbortError';
        throw err;
      },
      resolveCname: async () => [],
      resolve4: async () => ['198.51.100.10'],
      resolve6: async () => [],
    });
    assert.equal(result.request_error_class, 'probe_timeout');
  });

  it('rejects invalid hostnames before any network activity', async () => {
    let networkTouched = false;
    const result = await detectEdgeForHostname({
      hostname: 'https://evil.example/path',
      fetchFn: async () => {
        networkTouched = true;
        return mockResponse(200, {});
      },
    });
    assert.equal(result.error, 'invalid_hostname');
    assert.equal(result.status, 400);
    assert.equal(networkTouched, false);
  });

  it('never includes header values or body text in the result', async () => {
    const secretRay = 'ray-never-leak-42';
    const result = await detectEdgeForHostname({
      hostname: 'shop.example.test',
      fetchFn: async () => mockResponse(200, {
        'cf-ray': secretRay,
        __body: '<html>body-never-leak-42</html>',
      }),
      ...CLOUDFLARE_DNS,
    });
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes(secretRay));
    assert.ok(!serialized.includes('body-never-leak-42'));
  });

  it('uses http only for loopback hosts', async () => {
    const requestLog = [];
    await detectEdgeForHostname({
      hostname: 'localhost',
      fetchFn: async (url, init) => {
        requestLog.push({ url, init });
        return mockResponse(200, {});
      },
      resolveCname: async () => [],
      resolve4: async () => ['127.0.0.1'],
      resolve6: async () => [],
    });
    assert.ok(requestLog[0].url.startsWith('http://localhost/'));

    const secure = [];
    await detectEdgeForHostname({
      hostname: 'shop.example.test',
      fetchFn: async (url, init) => {
        secure.push({ url, init });
        return mockResponse(200, {});
      },
      ...CLOUDFLARE_DNS,
    });
    assert.ok(secure[0].url.startsWith('https://'));
  });
});
