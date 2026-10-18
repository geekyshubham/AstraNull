import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CONTROL_FAMILIES, REMEDIATION_PROVIDERS } from '../../src/contracts/missingControls/families.mjs';
import {
  PROVIDER_REMEDIATION,
  PROVIDER_LABELS,
  getProviderRemediation,
} from '../../src/contracts/providerRemediation.mjs';

const DOC_HOSTS = Object.freeze({
  gcp: ['cloud.google.com'],
  aws: ['docs.aws.amazon.com', 'aws.amazon.com'],
  azure: ['learn.microsoft.com'],
  cloudflare: ['developers.cloudflare.com'],
  akamai: ['techdocs.akamai.com'],
  fastly: ['docs.fastly.com', 'www.fastly.com'],
  generic: ['owasp.org', 'cheatsheetseries.owasp.org', 'www.rfc-editor.org', 'www.cisa.gov', 'www.nist.gov', 'csrc.nist.gov'],
});

const PLACEHOLDER = /\b(TODO|TBD|FIXME|XXX|placeholder|lorem ipsum)\b/i;
const families = Object.keys(CONTROL_FAMILIES);

function eachEntry(fn) {
  for (const family of families) {
    for (const provider of REMEDIATION_PROVIDERS) {
      fn(family, provider, PROVIDER_REMEDIATION[family]?.[provider]);
    }
  }
}

describe('provider remediation catalog', () => {
  it('covers every control family and provider and nothing else', () => {
    assert.deepEqual(Object.keys(PROVIDER_REMEDIATION).sort(), [...families].sort());
    for (const family of families) {
      assert.deepEqual(Object.keys(PROVIDER_REMEDIATION[family]).sort(), [...REMEDIATION_PROVIDERS].sort(), family);
    }
    let count = 0;
    eachEntry((family, provider, entry) => {
      assert.ok(entry, `${family}/${provider} missing`);
      count += 1;
    });
    assert.equal(count, families.length * REMEDIATION_PROVIDERS.length);
  });

  it('labels every provider', () => {
    assert.deepEqual(Object.keys(PROVIDER_LABELS).sort(), [...REMEDIATION_PROVIDERS].sort());
    for (const provider of REMEDIATION_PROVIDERS) {
      assert.equal(typeof PROVIDER_LABELS[provider], 'string');
      assert.ok(PROVIDER_LABELS[provider].length > 0);
    }
  });

  it('names a concrete control for each entry', () => {
    eachEntry((family, provider, entry) => {
      const where = `${family}/${provider}`;
      assert.deepEqual(Object.keys(entry).sort(), ['control', 'docs', 'steps'], where);
      assert.equal(typeof entry.control, 'string', where);
      assert.ok(entry.control.trim().length > 0, `${where} control empty`);
      assert.ok(entry.control.length <= 200, `${where} control too long`);
      assert.doesNotMatch(entry.control, PLACEHOLDER, where);
    });
  });

  it('gives 2 to 5 concrete steps per entry', () => {
    eachEntry((family, provider, entry) => {
      const where = `${family}/${provider}`;
      assert.ok(Array.isArray(entry.steps), where);
      assert.ok(entry.steps.length >= 2 && entry.steps.length <= 5, `${where} has ${entry.steps.length} steps`);
      assert.equal(new Set(entry.steps).size, entry.steps.length, `${where} duplicate steps`);
      for (const step of entry.steps) {
        assert.equal(typeof step, 'string', where);
        assert.ok(step.trim().length > 0, `${where} empty step`);
        assert.ok(step.length <= 300, `${where} step too long: ${step.length}`);
        assert.doesNotMatch(step, PLACEHOLDER, `${where}: ${step}`);
      }
    });
  });

  it('cites 1 to 3 official https docs on the provider allow-list', () => {
    eachEntry((family, provider, entry) => {
      const where = `${family}/${provider}`;
      assert.ok(Array.isArray(entry.docs), where);
      assert.ok(entry.docs.length >= 1 && entry.docs.length <= 3, `${where} has ${entry.docs.length} docs`);
      assert.equal(new Set(entry.docs).size, entry.docs.length, `${where} duplicate docs`);
      for (const doc of entry.docs) {
        const url = new URL(doc);
        assert.equal(url.protocol, 'https:', `${where}: ${doc}`);
        assert.ok(DOC_HOSTS[provider].includes(url.hostname), `${where}: ${url.hostname} not allowed`);
      }
    });
  });

  it('keeps generic guidance vendor-neutral', () => {
    const vendorTerms = /\b(Cloud Armor|AWS|Azure|Cloudflare|Akamai|Fastly|gcloud|Google)\b/;
    for (const family of families) {
      const entry = PROVIDER_REMEDIATION[family].generic;
      assert.doesNotMatch(entry.control, vendorTerms, family);
      for (const step of entry.steps) assert.doesNotMatch(step, vendorTerms, `${family}: ${step}`);
    }
  });

  it('returns entries by family and provider', () => {
    assert.equal(
      getProviderRemediation('network_firewall_ingress', 'gcp'),
      PROVIDER_REMEDIATION.network_firewall_ingress.gcp,
    );
    assert.equal(getProviderRemediation('waf_rate_limiting', 'aws').control, 'AWS WAF rate-based rules');
  });

  it('returns null for unknown family or provider', () => {
    assert.equal(getProviderRemediation('unknown_family', 'gcp'), null);
    assert.equal(getProviderRemediation('waf_rate_limiting', 'oracle'), null);
    assert.equal(getProviderRemediation('waf_rate_limiting', 'toString'), null);
    assert.equal(getProviderRemediation('__proto__', 'gcp'), null);
    assert.equal(getProviderRemediation(undefined, undefined), null);
  });

  it('freezes the catalog at every level', () => {
    assert.ok(Object.isFrozen(PROVIDER_REMEDIATION));
    assert.ok(Object.isFrozen(PROVIDER_LABELS));
    eachEntry((family, provider, entry) => {
      const where = `${family}/${provider}`;
      assert.ok(Object.isFrozen(PROVIDER_REMEDIATION[family]), family);
      assert.ok(Object.isFrozen(entry), where);
      assert.ok(Object.isFrozen(entry.steps), where);
      assert.ok(Object.isFrozen(entry.docs), where);
    });
    assert.throws(() => PROVIDER_REMEDIATION.network_firewall_ingress.gcp.steps.push('x'), TypeError);
  });
});
