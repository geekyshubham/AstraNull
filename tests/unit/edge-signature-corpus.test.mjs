import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CDN_ADDRESS_RANGES,
  EDGE_CNAME_SUFFIXES,
  EDGE_CORPUS_STATS,
  WAF_ADDRESS_RANGES,
  WAF_VENDOR_SIGNATURES,
} from '../../src/lib/data/edgeSignatureData.mjs';
import {
  EDGE_SIGNATURE_CORPUS_VERSION,
  extractFingerprintHeaderEntries,
} from '../../src/lib/edgeFingerprint.mjs';

const TIERS = new Set(['passive', 'block_page']);
const SIGNALS = new Set(['header', 'cookie', 'content', 'status', 'reason']);

// Guard against attack-payload-style strings ever entering the corpus. Block-page
// content patterns describe vendor response text (e.g. "Access Denied"), never
// reusable exploit payloads.
const PAYLOAD_LIKE = [
  /<script[^>]*>/i,
  /union\s+select/i,
  /\.\.\/\.\.\//,
  /javascript:/i,
  /onerror\s*=/i,
  /\bor\s+1\s*=\s*1\b/i,
];

function corpusSignatures() {
  const rows = [];
  for (const [vendor, vendorData] of Object.entries(WAF_VENDOR_SIGNATURES)) {
    for (const sig of vendorData.signatures ?? []) {
      rows.push({ vendor, ...sig });
    }
  }
  return rows;
}

describe('edge signature corpus (wafw00f + cdncheck port)', () => {
  it('exports a corpus version and stats that match the data', () => {
    assert.ok(EDGE_SIGNATURE_CORPUS_VERSION.length > 0);
    const sigs = corpusSignatures();
    assert.equal(EDGE_CORPUS_STATS.waf_vendors, Object.keys(WAF_VENDOR_SIGNATURES).length);
    assert.equal(EDGE_CORPUS_STATS.passive_signatures, sigs.filter((s) => s.tier === 'passive').length);
    assert.equal(EDGE_CORPUS_STATS.block_page_signatures, sigs.filter((s) => s.tier === 'block_page').length);
    const countRanges = (group) => Object.values(group).reduce((sum, v) => sum + v.length, 0);
    assert.equal(EDGE_CORPUS_STATS.cdn_ranges, countRanges(CDN_ADDRESS_RANGES));
    assert.equal(EDGE_CORPUS_STATS.waf_ranges, countRanges(WAF_ADDRESS_RANGES));
    assert.equal(EDGE_CORPUS_STATS.cname_suffixes, countRanges(EDGE_CNAME_SUFFIXES));
  });

  it('ports a substantive vendor corpus', () => {
    assert.ok(Object.keys(WAF_VENDOR_SIGNATURES).length >= 150);
    assert.ok(corpusSignatures().filter((s) => s.tier === 'passive').length >= 150);
  });

  it('keeps every signature within the declared tier/signal vocabulary', () => {
    for (const sig of corpusSignatures()) {
      assert.ok(TIERS.has(sig.tier), `unexpected tier ${sig.tier} on ${sig.vendor}`);
      assert.ok(SIGNALS.has(sig.signal), `unexpected signal ${sig.signal} on ${sig.vendor}`);
    }
  });

  it('keeps passive signatures free of payload-like content', () => {
    for (const sig of corpusSignatures()) {
      const pattern = String(sig.pattern ?? sig.value ?? '');
      for (const marker of PAYLOAD_LIKE) {
        assert.ok(!marker.test(pattern), `payload-like signature in ${sig.vendor}: ${pattern}`);
      }
    }
  });

  it('lowercases exact-match header names and keeps ranges provider-keyed', () => {
    for (const sig of corpusSignatures()) {
      if (sig.signal !== 'header') continue;
      if (/^[a-z0-9-]+$/.test(sig.header)) continue;
      // Non-literal names must at least be lowercase-ish regex fragments from upstream.
      assert.equal(sig.header, sig.header.toLowerCase(), `unexpected mixed-case header name ${sig.header}`);
    }
    for (const group of [CDN_ADDRESS_RANGES, WAF_ADDRESS_RANGES]) {
      for (const [provider, ranges] of Object.entries(group)) {
        assert.ok(provider.length > 0);
        assert.ok(Array.isArray(ranges) && ranges.length > 0, `empty range list for ${provider}`);
      }
    }
  });

  it('bounds and allowlists fingerprint header extraction', () => {
    const longValue = 'v'.repeat(500);
    const seen = [];
    const headers = {
      get: (name) => {
        seen.push(name);
        if (name === 'server') return longValue;
        if (name === 'set-cookie') return 'should-not-be-read=1';
        if (name === 'x-custom-header') return 'not-in-corpus';
        return null;
      },
    };
    const entries = extractFingerprintHeaderEntries({ headers });
    const serverEntry = entries.find((e) => e.name === 'server');
    assert.ok(serverEntry, 'server is a corpus header and must be captured');
    assert.ok(serverEntry.value.length <= 128, 'captured header values must be truncated');
    assert.ok(!seen.includes('set-cookie'), 'cookie values must never be read');
    assert.ok(!seen.includes('x-custom-header'), 'only corpus allowlisted headers may be read');
    assert.ok(!entries.some((e) => e.name === 'x-custom-header'));
  });
});
