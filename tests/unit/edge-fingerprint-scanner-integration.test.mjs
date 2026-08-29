import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { runOutsideInWafScan } from '../../src/lib/outsideInWafScanner.mjs';
import { EDGE_SIGNATURE_CORPUS_VERSION } from '../../src/lib/edgeFingerprint.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../src/lib/wafProductCatalog.mjs';

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

const TLS_STUB = (options) => {
  const handlers = {};
  const socket = {
    destroy() {},
    once(event, fn) { handlers[event] = fn; },
    getProtocol: () => 'TLSv1.3',
    getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }),
  };
  queueMicrotask(() => handlers.secureConnect?.());
  return socket;
};

describe('outside-in WAF scanner — edge signature corpus integration', () => {
  it('classifies a Cloudflare edge from passive headers and CDN range evidence', async () => {
    const cfRay = 'ray-value-never-persist-42';
    const outcome = await runOutsideInWafScan({
      url: 'https://shop.example.test/',
      hostname: 'shop.example.test',
      budget: 4,
      timeoutMs: 500,
      resolveCname: async () => ['edge.example.net'],
      resolve4: async () => ['108.138.5.5'],
      tlsConnect: TLS_STUB,
      fetchFn: async () => mockResponse(200, {
        server: 'cloudflare',
        'cf-ray': cfRay,
        'set-cookie': '__cfduid=abc; Path=/',
      }),
    });

    assert.equal(outcome.edge_signature_corpus_version, EDGE_SIGNATURE_CORPUS_VERSION);
    assert.equal(outcome.edge_signature.best_vendor.vendor, 'cloudflare');
    assert.ok(outcome.edge_signature.best_vendor.confidence >= 0.85);
    assert.equal(outcome.edge_signature.waf_present, true);
    assert.deepEqual(
      outcome.edge_signature.address_matches,
      [{ family: 'cdn', provider: 'cloudfront' }],
    );
    assert.equal(outcome.edge_signature.cdn_detected, true);
    assert.equal(outcome.waf_detected, true);
    assert.equal(outcome.cdn_detected, true);
    assert.equal(outcome.edge_signature_corpus_version, '1');
  });

  it('adds block-page vendor classification from an authorized blocked marker response', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://shop.example.test/',
      hostname: 'shop.example.test',
      budget: 3,
      timeoutMs: 500,
      resolveCname: async () => [],
      resolve4: async () => ['198.51.100.10'],
      tlsConnect: TLS_STUB,
      fetchFn: async (url) => {
        if (String(url).includes('=')) {
          return mockResponse(403, { server: 'openresty' }, { __body: 'ModSecurity Action' });
        }
        return mockResponse(200, { server: 'openresty' });
      },
    });

    assert.ok(outcome.edge_signature.vendor_matches.some((m) => m.vendor === 'modsecurity'));
    assert.ok(
      outcome.edge_signature.vendor_matches
        .find((m) => m.vendor === 'modsecurity')
        .matched_signals
        .every((s) => s.tier === 'block_page'),
    );
  });

  it('reports no corpus classification on a plain origin response', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://shop.example.test/',
      hostname: 'shop.example.test',
      budget: 2,
      timeoutMs: 500,
      resolveCname: async () => [],
      resolve4: async () => ['198.51.100.10'],
      tlsConnect: TLS_STUB,
      fetchFn: async () => mockResponse(200, { server: 'nginx/1.24.0' }),
    });

    assert.equal(outcome.edge_signature.waf_present, false);
    assert.equal(outcome.edge_signature.best_vendor, null);
    assert.deepEqual(outcome.edge_signature.address_matches, []);
    assert.equal(outcome.cdn_detected, false);
  });

  it('never persists fingerprint header values or body text in the scan result', async () => {
    const bodyText = 'block-page-body-never-persist-42';
    const ray = 'ray-never-persist-42';
    const outcome = await runOutsideInWafScan({
      url: 'https://shop.example.test/',
      hostname: 'shop.example.test',
      budget: 3,
      timeoutMs: 500,
      resolveCname: async () => [],
      resolve4: async () => ['198.51.100.10'],
      tlsConnect: TLS_STUB,
      fetchFn: async (url) => {
        if (String(url).includes('=')) {
          return mockResponse(403, { 'cf-ray': ray, __body: bodyText });
        }
        return mockResponse(200, { 'cf-ray': ray });
      },
    });

    const serialized = JSON.stringify(outcome);
    assert.ok(!serialized.includes(bodyText), 'body text must not leak into scan results');
    assert.ok(!serialized.includes(ray), 'captured header values must not leak into scan results');
    assert.ok(serialized.includes('block_page_fingerprint_hash'));
  });

  it('stamps edge corpus metadata onto signed fingerprint probe jobs', () => {
    const metadata = enrichProbeMetadataWithWafCatalog({}, 'waf.fingerprint.safe');
    assert.equal(metadata.edge_signature_corpus_version, EDGE_SIGNATURE_CORPUS_VERSION);
    assert.equal(metadata.edge_signature_waf_vendors > 150, true);
    assert.ok(metadata.waf_fingerprint_catalog_version);

    const untouched = enrichProbeMetadataWithWafCatalog({ existing: true }, 'det.origin_bypass.safe');
    assert.deepEqual(untouched, { existing: true });
  });
});
