import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  EDGE_SIGNATURE_CORPUS_VERSION,
  classifyEdgeByAddress,
  classifyEdgeByCnameChain,
  classifyEdgeFingerprint,
  classifyWafVendorsFromResponseEvidence,
} from '../../src/lib/edgeFingerprint.mjs';

describe('edge fingerprint classifier (wafw00f tier logic)', () => {
  it('matches multiple passive signals for a vendor', () => {
    const result = classifyWafVendorsFromResponseEvidence({
      headerEntries: [
        { name: 'server', value: 'cloudflare' },
        { name: 'cf-ray', value: '8a1b2c3d4e5f' },
      ],
      cookieNames: ['__cfduid', 'session'],
    });
    assert.equal(result.best.vendor, 'cloudflare');
    assert.ok(result.best.confidence >= 0.85);
    assert.equal(result.best.matched_signals.filter((s) => s.tier === 'passive').length, 3);
    assert.equal(result.conflicting_vendor_signals, false);
  });

  it('does not evaluate block-page signatures without captured block evidence', () => {
    const evidence = {
      statusCode: 403,
      statusReason: 'ModSecurity Action',
      bodyText: 'ModSecurity Action — request blocked',
    };
    const withoutBlock = classifyWafVendorsFromResponseEvidence(evidence);
    assert.equal(withoutBlock.best, null);
    assert.equal(withoutBlock.matches.length, 0);

    const withBlock = classifyWafVendorsFromResponseEvidence({ ...evidence, blockResponse: true });
    assert.ok(withBlock.best);
    assert.equal(withBlock.best.vendor, 'modsecurity');
    assert.ok(withBlock.best.matched_signals.every((s) => s.tier === 'block_page'));
  });

  it('matches content, status, and reason block signals only on block responses', () => {
    const withBlock = classifyWafVendorsFromResponseEvidence({
      statusCode: 403,
      bodyText: 'Access Denied — Reference #12.abc',
      statusReason: 'Forbidden',
      blockResponse: true,
    });
    const vendors = new Set(withBlock.matches.map((m) => m.vendor));
    assert.ok(vendors.size >= 1);
    for (const match of withBlock.matches) {
      assert.ok(match.matched_signals.every((s) => s.tier === 'block_page'));
    }
  });

  it('ignores a block status on a normal (non-block) response', () => {
    const result = classifyWafVendorsFromResponseEvidence({ statusCode: 403 });
    assert.equal(result.best, null);
  });

  it('flags conflicting vendor signals when two vendors tie', () => {
    const result = classifyWafVendorsFromResponseEvidence({
      headerEntries: [
        { name: 'server', value: 'cloudflare' },
        { name: 'x-dis-request-id', value: 'abc123' },
      ],
    });
    const vendors = new Set(result.matches.map((m) => m.vendor));
    assert.ok(vendors.has('cloudflare'));
    assert.ok(vendors.has('dosarrest'));
    assert.equal(result.conflicting_vendor_signals, true);
  });

  it('returns no matches for unrelated evidence', () => {
    const result = classifyWafVendorsFromResponseEvidence({
      headerEntries: [{ name: 'content-type', value: 'text/html' }],
      cookieNames: ['prefer'],
      bodyText: '<html><body>hello</body></html>',
      statusCode: 200,
    });
    assert.equal(result.best, null);
    assert.equal(result.matches.length, 0);
  });

  it('is deterministic for identical evidence', () => {
    const evidence = {
      headerEntries: [{ name: 'server', value: 'cloudflare' }],
      cookieNames: ['__cfduid'],
    };
    const first = classifyWafVendorsFromResponseEvidence(evidence);
    const second = classifyWafVendorsFromResponseEvidence(evidence);
    assert.deepEqual(first, second);
  });
});

describe('edge fingerprint address + CNAME classification (cdncheck port)', () => {
  it('classifies IPv4 addresses against CDN ranges', () => {
    assert.deepEqual(classifyEdgeByAddress('108.138.5.5'), [
      { family: 'cdn', provider: 'cloudfront' },
    ]);
  });

  it('classifies IPv6 addresses against CDN ranges', () => {
    const hits = classifyEdgeByAddress('2a04:4e40::1');
    assert.deepEqual(hits, [{ family: 'cdn', provider: 'fastly' }]);
  });

  it('classifies WAF range membership', () => {
    const hits = classifyEdgeByAddress('103.153.100.1');
    assert.ok(Array.isArray(hits));
    assert.ok(hits.every((h) => h.family === 'waf' || h.family === 'cdn'));
  });

  it('returns no hits for non-edge addresses', () => {
    // 8.8.8.8 IS in the upstream corpus (google 8.8.8.0/24) — pick a documentation
    // range that no provider claims.
    const hits = classifyEdgeByAddress(['198.51.100.10', '203.0.113.7', 'not-an-ip', '']);
    assert.equal(hits.length, 0);
  });

  it('matches CNAME chains by provider suffix', () => {
    const hits = classifyEdgeByCnameChain(['www.example.com', 'example.com.akamaiedge.net']);
    assert.deepEqual(hits, [{ provider: 'akamai', suffix: 'akamaiedge.net' }]);
  });

  it('does not treat IP literals as CNAME candidates', () => {
    assert.deepEqual(classifyEdgeByCnameChain(['192.0.2.10']), []);
  });
});

describe('combined edge fingerprint', () => {
  it('combines vendor, address, and CNAME classification with provenance', () => {
    const result = classifyEdgeFingerprint({
      headerEntries: [{ name: 'server', value: 'cloudflare' }],
      resolvedIps: ['108.138.5.5'],
      cnameChain: ['example.com.akamaiedge.net'],
    });
    assert.equal(result.corpus_version, EDGE_SIGNATURE_CORPUS_VERSION);
    assert.equal(result.metadata_only, true);
    assert.equal(result.waf_present, true);
    assert.equal(result.cdn_detected, true);
    assert.equal(result.best_vendor.vendor, 'cloudflare');
    assert.deepEqual(result.address_matches, [{ family: 'cdn', provider: 'cloudfront' }]);
    assert.ok(result.cname_matches.some((m) => m.provider === 'akamai'));
  });

  it('reports neither WAF nor CDN on plain origin evidence', () => {
    const result = classifyEdgeFingerprint({
      headerEntries: [{ name: 'server', value: 'nginx/1.24.0' }],
      resolvedIps: ['198.51.100.10'],
      cnameChain: ['origin.internal.example.test'],
    });
    assert.equal(result.waf_present, false);
    assert.equal(result.cdn_detected, false);
    assert.equal(result.best_vendor, null);
    assert.deepEqual(result.vendor_matches, []);
  });

  it('never reports waf_present from block responses without a vendor signal', () => {
    const result = classifyEdgeFingerprint({
      statusCode: 429,
      bodyText: 'totally-unique-nonmatching-text-xyzzy',
      blockResponse: true,
    });
    assert.equal(result.waf_present, false);
    assert.equal(result.best_vendor, null);
    assert.equal(result.vendor_matches.length, 0);
  });

  it('keeps waf address membership without a vendor signature', async () => {
    const { WAF_ADDRESS_RANGES } = await import('../../src/lib/data/edgeSignatureData.mjs');
    const wafRange = Object.entries(WAF_ADDRESS_RANGES)
      .flatMap(([provider, ranges]) => ranges.map((r) => ({ provider, r })))
      .find(({ r }) => !r.includes(':') && classifyEdgeByAddress(r.split('/')[0]).some((h) => h.family === 'waf'));
    assert.ok(wafRange, 'corpus must contain a waf-only range for this test');
    const result = classifyEdgeFingerprint({ resolvedIps: [wafRange.r.split('/')[0]] });
    assert.equal(result.waf_present, true);
    assert.equal(result.best_vendor, null);
  });
});
