import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { normalizeRemediationProvider, projectMissingControl } from '../../src/lib/missingControlProjection.mjs';

const edge = (overrides = {}) => ({
  waf: { status: 'not_detected' }, cdn: { status: 'not_detected' }, cloud: { status: 'not_detected' },
  waf_providers: [], cdn_providers: [], cloud_providers: [], ...overrides,
});

describe('missing-control projection', () => {
  it('projects every catalog check with generic guidance when no provider is detected', () => {
    for (const check of CHECK_CATALOG) {
      const projection = projectMissingControl({ checkId: check.check_id, gap: true });
      assert.ok(projection, check.check_id);
      assert.equal(projection.status, 'missing');
      assert.equal(projection.attribution, 'unattributed');
      assert.equal(projection.headline, `Missing control: ${projection.control_label}`);
      assert.deepEqual(projection.provider_guidance.map((row) => row.provider), ['generic'], check.check_id);
      assert.ok(projection.provider_guidance[0].steps.length >= 2);
    }
  });

  it('puts the detected cloud provider first for a network firewall gap and ignores the CDN layer', () => {
    const projection = projectMissingControl({
      checkId: 'nfw.management_port_exposure.safe',
      explanation: 'Declared deny for tcp/3389 (ipv4) from external probe was violated; denial cannot be proven from outside.',
      edgeDetection: edge({ cloud: { status: 'detected', provider: 'gcp' }, cdn: { status: 'detected', provider: 'cloudflare' } }),
      gap: true,
    });
    assert.equal(projection.control_family, 'network_firewall_ingress');
    assert.deepEqual(projection.provider_guidance.map((row) => row.provider), ['gcp', 'generic']);
    assert.equal(projection.provider_guidance[0].source, 'detected_edge');
    assert.equal(projection.provider_guidance[0].detection_layer, 'cloud');
    assert.match(projection.observed, /tcp\/3389/);
    assert.deepEqual(projection.other_provider_guidance.map((row) => row.provider), ['aws', 'azure', 'cloudflare', 'akamai', 'fastly']);
    assert.ok(projection.other_provider_guidance.every((row) => row.source === 'catalog' && row.detected_as === null));
  });

  it('orders WAF then CDN providers for an edge WAF gap and maps vendor aliases', () => {
    const projection = projectMissingControl({
      checkId: 'waf.sqli_managed_marker.safe',
      edgeDetection: edge({ waf: { status: 'detected', provider: 'awswaf' }, cdn: { status: 'detected', provider: 'cloudfront' }, cdn_providers: ['akamai'] }),
      gap: true,
    });
    assert.deepEqual(projection.provider_guidance.map((row) => row.provider), ['aws', 'akamai', 'generic']);
    assert.equal(projection.provider_guidance[0].detected_as, 'awswaf');
  });

  it('reports a detected vendor without catalog guidance instead of guessing', () => {
    const projection = projectMissingControl({
      checkId: 'waf.sqli_managed_marker.safe',
      edgeDetection: edge({ waf: { status: 'detected', provider: 'incapsula' } }),
      gap: true,
    });
    assert.deepEqual(projection.detected_without_guidance, ['incapsula']);
    assert.deepEqual(projection.provider_guidance.map((row) => row.provider), ['generic']);
  });

  it('is not_established without a gap and null for unknown checks', () => {
    assert.equal(projectMissingControl({ checkId: 'waf.sqli_managed_marker.safe', verdict: 'protected' }).status, 'not_established');
    assert.equal(projectMissingControl({ checkId: 'waf.sqli_managed_marker.safe', verdict: { verdict: 'exposed', explanation: 'x' } }).status, 'missing');
    assert.equal(projectMissingControl({ checkId: 'no.such.check' }), null);
  });

  it('reads providers from the presented layers array and multi-word vendor names', () => {
    const projection = projectMissingControl({
      checkId: 'waf.sqli_managed_marker.safe',
      edgeDetection: edge({ layers: [{ family: 'waf', provider: 'AWS WAF' }, { family: 'cloud', provider: 'gcp' }] }),
      gap: true,
    });
    assert.deepEqual(projection.provider_guidance.map((row) => row.provider), ['aws', 'generic']);
    assert.equal(projection.provider_guidance[0].detected_as, 'AWS WAF');
  });

  it('normalizes provider aliases and rejects unknown vendors', () => {
    assert.equal(normalizeRemediationProvider('Azure Front Door'), 'azure');
    assert.equal(normalizeRemediationProvider('google'), 'gcp');
    assert.equal(normalizeRemediationProvider('Amazon CloudFront'), 'aws');
    assert.equal(normalizeRemediationProvider('Microsoft Azure'), 'azure');
    assert.equal(normalizeRemediationProvider('sucuri'), null);
  });
});
