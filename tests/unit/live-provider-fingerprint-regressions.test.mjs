import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { runOutsideInWafScan } from '../../src/lib/outsideInWafScanner.mjs';
import { projectEdgeDetection, edgeDetectionRowFields } from '../../src/lib/edgeDetectionProjection.mjs';
import { presentTargetEdgeDetection } from '../../src/lib/edgeDetectionPresenter.mjs';

// Metadata-only fixtures from ordinary GET/DNS observations on 2026-10-08; no live test traffic.
const fixtures = [
  { host: 'qantas.com', ips: ['23.206.173.51', '23.206.173.26'], chain: ['qantas.com'], timeout: true, cdn: 'akamai' },
  { host: 'www.qantas.com', ips: ['23.206.173.51'], chain: ['www.qantas.com', 'www.qantas.com.edgekey.net', 'e72018.x.akamaiedge.net'], timeout: true, cdn: 'akamai' },
  { host: 'westpac.com.au', ips: ['13.225.5.5'], chain: ['westpac.com.au'], status: 301, server: 'CloudFront', cdn: 'cloudfront' },
  { host: 'www.westpac.com.au', ips: ['13.225.5.5'], chain: ['www.westpac.com.au', 'dplenhq18279.cloudfront.net'], status: 200, server: 'CloudFront', cdn: 'cloudfront' },
  { host: 'www.westpac.com.au', ips: ['18.165.83.68'], chain: ['www.westpac.com.au', 'dplenhq18279.cloudfront.net'], status: 200, server: 'CloudFront', cdn: 'cloudfront', fastly: true },
  { host: 'jagex.com', ips: ['31.43.161.19', '31.43.160.19'], chain: ['jagex.com'], status: 308, server: 'Framer/26fa766', cdn: 'framer' },
  { host: 'www.jagex.com', ips: ['104.18.40.92', '172.64.147.164'], chain: ['www.jagex.com', 'www.jagex.com.cdn.cloudflare.net'], status: 200, server: 'cloudflare', cdn: 'cloudflare', waf: true },
];

describe('Qantas, Westpac and Jagex fingerprint regressions', () => {
  for (const fixture of fixtures) {
    it(`preserves scoped provider evidence and zero enforcement claims for ${fixture.host}`, async () => {
      let requests = 0;
      const scan = await runOutsideInWafScan({
        url: `https://${fixture.host}/`, hostname: fixture.host,
        fingerprintOnly: true, budget: 1, timeoutMs: 100,
        collectNetworkHints: false, followRedirects: false,
        resolvedIps: fixture.ips, cnameChain: fixture.chain,
        fetchFn: async () => {
          requests += 1;
          if (fixture.timeout) throw Object.assign(new Error('timeout'), { name: 'AbortError' });
          return { status: fixture.status, headers: new Headers({ server: fixture.server,
            ...(fixture.fastly ? { 'x-served-by': 'cache-iad-kiad7000138-IAD, cache-lga-kjfk8660077-LGA' } : {}),
          }), text: async () => '' };
        },
      });
      const result = projectEdgeDetection(scan);
      const presented = presentTargetEdgeDetection(edgeDetectionRowFields(result));
      assert.equal(requests, 1);
      assert.equal(presented.cdn.provider, fixture.cdn);
      assert.equal(presented.waf.status, fixture.timeout ? 'inconclusive' : fixture.waf ? 'detected' : 'not_detected');
      assert.equal(presented.protection.status, fixture.waf ? 'detected_only' : 'inconclusive');
      assert.equal(presented.effectiveness.tested_count, 0);
      assert.equal(presented.effectiveness.percentage, null);
      assert.equal(scan.waf_detected, fixture.waf === true);
      if (fixture.fastly) assert.deepEqual(presented.cdn_providers, ['cloudfront', 'fastly']);
      if (!fixture.waf) assert.equal(scan.detected_vendor, null);
      if (fixture.timeout) {
        assert.equal(presented.status, 'inconclusive');
        assert.doesNotMatch(presented.plain_language_summary, /No WAF was detected/);
      }
    });
  }
});
