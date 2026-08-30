import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { extractWafPluginPrograms } from '../../scripts/generate-edge-signatures.mjs';
import {
  CDN_ADDRESS_RANGES,
  EDGE_CNAME_RULES,
  EDGE_CORPUS_STATS,
  EDGE_SIGNATURE_CORPUS_MANIFEST,
  WAF_ADDRESS_RANGES,
  WAF_VENDOR_SIGNATURES,
} from '../../src/lib/data/edgeSignatureData.mjs';
import {
  EDGE_SIGNATURE_CORPUS_VERSION,
  extractFingerprintHeaderEntries,
} from '../../src/lib/edgeFingerprint.mjs';

const TIERS = new Set(['passive', 'block_page']);
const SIGNALS = new Set(['header', 'cookie', 'content', 'status', 'reason']);
const MATCHER_OPS = new Set(['const', 'signal', 'not', 'and', 'or', 'if']);
const REQUIRED_COMPOUND_PLUGINS = ['applicationgateway', 'kemp', 'reflected', 'threatx'];
const OUTPUT_MANIFEST = JSON.parse(readFileSync(
  new URL('../../src/lib/data/edgeSignatureData.manifest.json', import.meta.url),
  'utf8',
));

const PAYLOAD_LIKE = [
  /<script[^>]*>/i,
  /union\s+select/i,
  /\.\.\/\.\.\//,
  /javascript:/i,
  /onerror\s*=/i,
  /\bor\s+1\s*=\s*1\b/i,
];

function corpusSignatures() {
  return Object.entries(WAF_VENDOR_SIGNATURES).flatMap(([vendor, data]) => (
    (data.signatures ?? []).map((signature) => ({ vendor, ...signature }))
  ));
}

function countEntries(group) {
  return Object.values(group).reduce((sum, values) => sum + values.length, 0);
}

function validateMatcher(node, signatureCount, referenced) {
  assert.ok(node && MATCHER_OPS.has(node.op), `invalid matcher op ${node?.op}`);
  if (node.op === 'signal') {
    assert.ok(Number.isInteger(node.id) && node.id >= 0 && node.id < signatureCount);
    referenced.add(node.id);
  } else if (node.op === 'not') {
    validateMatcher(node.arg, signatureCount, referenced);
  } else if (node.op === 'and' || node.op === 'or') {
    assert.ok(Array.isArray(node.args) && node.args.length >= 2);
    for (const child of node.args) validateMatcher(child, signatureCount, referenced);
  } else if (node.op === 'if') {
    validateMatcher(node.condition, signatureCount, referenced);
    validateMatcher(node.then, signatureCount, referenced);
    validateMatcher(node.else, signatureCount, referenced);
  } else if (node.op === 'const') {
    assert.equal(typeof node.value, 'boolean');
  }
}

function sha256File(relativePath) {
  return createHash('sha256')
    .update(readFileSync(new URL(`../../${relativePath}`, import.meta.url)))
    .digest('hex');
}

describe('edge signature corpus provenance and inventory', () => {
  it('embeds exact commits, inputs, generator bytes, output hash, notices, and versions', () => {
    assert.equal(EDGE_SIGNATURE_CORPUS_VERSION, '2');
    assert.equal(EDGE_SIGNATURE_CORPUS_MANIFEST.output_version, 2);
    assert.equal(EDGE_SIGNATURE_CORPUS_MANIFEST.format, 'astranull-edge-signature-corpus-v2');
    assert.equal(
      EDGE_SIGNATURE_CORPUS_MANIFEST.output_manifest,
      'src/lib/data/edgeSignatureData.manifest.json',
    );

    assert.equal(OUTPUT_MANIFEST.manifest_version, 1);
    assert.equal(OUTPUT_MANIFEST.format, 'astranull-edge-signature-corpus-manifest-v1');
    assert.equal(OUTPUT_MANIFEST.output_version, 2);
    assert.equal(OUTPUT_MANIFEST.generator.path, 'scripts/generate-edge-signatures.mjs');
    assert.equal(OUTPUT_MANIFEST.generator.sha256, sha256File(OUTPUT_MANIFEST.generator.path));
    assert.equal(
      EDGE_SIGNATURE_CORPUS_MANIFEST.generator_sha256,
      OUTPUT_MANIFEST.generator.sha256,
    );
    assert.equal(OUTPUT_MANIFEST.output.path, 'src/lib/data/edgeSignatureData.mjs');
    assert.equal(OUTPUT_MANIFEST.output.sha256, sha256File(OUTPUT_MANIFEST.output.path));
    assert.equal(
      OUTPUT_MANIFEST.output.bytes,
      readFileSync(new URL(`../../${OUTPUT_MANIFEST.output.path}`, import.meta.url)).byteLength,
    );

    const { wafw00f, cdncheck } = EDGE_SIGNATURE_CORPUS_MANIFEST.sources;
    assert.equal(wafw00f.commit, '69fbe3956bba47a172cf87e40e9037535d32a130');
    assert.equal(cdncheck.commit, 'dac12984ef12fa5663c2b7591d0a304ef27c659b');
    assert.equal(wafw00f.plugin_tree_sha256, '44f4379d119d7cd688b2b8f68e5a1cd9e5bcf150491f46cb438d8a71f223b002');
    assert.equal(cdncheck.sources_data_sha256, '4a7482b64ded7a611e11eadda6730cc8df159942c16713f17bbfecdb8a7cd2a3');
    assert.equal(cdncheck.cname_implementation_sha256, '37182c8c3bc5a6182f2ced734d00fb252c5b0ae08cf284bd0437f44bc305244a');
    assert.equal(cdncheck.cname_item_type, 'waf');
    assert.deepEqual(cdncheck.ported_categories, ['cdn', 'waf', 'common']);
    assert.deepEqual(cdncheck.excluded_categories, [{
      category: 'cloud',
      reason: 'general hosting ranges are not edge-protection evidence',
    }]);
    assert.equal(OUTPUT_MANIFEST.sources.cdncheck.commit, cdncheck.commit);
    assert.deepEqual(OUTPUT_MANIFEST.sources.cdncheck.ported_categories, ['cdn', 'waf', 'common']);
    assert.deepEqual(OUTPUT_MANIFEST.sources.cdncheck.excluded_categories, cdncheck.excluded_categories);
    assert.deepEqual(OUTPUT_MANIFEST.sources.cdncheck.inputs, [
      { path: 'sources_data.json', sha256: cdncheck.sources_data_sha256 },
      { path: 'other.go', sha256: cdncheck.cname_implementation_sha256 },
      { path: 'LICENSE.md', sha256: cdncheck.license_sha256 },
    ]);

    assert.equal(sha256File(wafw00f.license_notice), wafw00f.license_sha256);
    assert.equal(sha256File(cdncheck.license_notice), cdncheck.license_sha256);
    assert.match(readFileSync(new URL('../../THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt', import.meta.url), 'utf8'), /THIS SOFTWARE IS PROVIDED[\s\S]+EVEN IF ADVISED/);
    assert.match(readFileSync(new URL('../../THIRD_PARTY_NOTICES/cdncheck-MIT.txt', import.meta.url), 'utf8'), /Permission is hereby granted[\s\S]+THE SOFTWARE IS PROVIDED/);
  });

  it('matches the complete pinned source inventories exactly', () => {
    const signatures = corpusSignatures();
    const pluginFiles = OUTPUT_MANIFEST.sources.wafw00f.plugin_files;
    const expectedPluginKeys = pluginFiles.map(({ path: pluginPath }) => (
      path.posix.basename(pluginPath, '.py')
    ));
    assert.equal(pluginFiles.length, 172);
    assert.equal(new Set(pluginFiles.map((entry) => entry.path)).size, 172);
    assert.equal(new Set(pluginFiles.map((entry) => entry.sha256)).size, 172);
    for (const entry of pluginFiles) {
      assert.match(entry.path, /^wafw00f\/plugins\/[a-z0-9_]+\.py$/);
      assert.match(entry.sha256, /^[a-f0-9]{64}$/);
    }
    assert.deepEqual(Object.keys(WAF_VENDOR_SIGNATURES), expectedPluginKeys);
    assert.equal(
      OUTPUT_MANIFEST.sources.wafw00f.commit,
      EDGE_SIGNATURE_CORPUS_MANIFEST.sources.wafw00f.commit,
    );
    assert.equal(
      OUTPUT_MANIFEST.sources.wafw00f.plugin_tree_sha256,
      EDGE_SIGNATURE_CORPUS_MANIFEST.sources.wafw00f.plugin_tree_sha256,
    );
    assert.equal(OUTPUT_MANIFEST.sources.wafw00f.matcher_calls, 518);
    assert.equal(OUTPUT_MANIFEST.sources.wafw00f.supported_plugins, 172);
    assert.equal(OUTPUT_MANIFEST.sources.wafw00f.unsupported_plugins, 0);
    assert.deepEqual(EDGE_CORPUS_STATS, {
      waf_plugins_total: 172,
      waf_plugins_supported: 172,
      waf_plugins_unsupported: 0,
      waf_vendors: 172,
      passive_signatures: 188,
      block_page_signatures: 330,
      cdn_providers: 16,
      waf_range_providers: 3,
      cname_providers: 32,
      cdn_ranges: 2462,
      waf_ranges: 1071,
      cname_suffixes: 103,
    });
    assert.equal(Object.keys(WAF_VENDOR_SIGNATURES).length, 172);
    assert.equal(signatures.length, 518);
    assert.equal(signatures.filter((signature) => signature.tier === 'passive').length, 188);
    assert.equal(signatures.filter((signature) => signature.tier === 'block_page').length, 330);
    assert.equal(countEntries(CDN_ADDRESS_RANGES), 2462);
    assert.equal(countEntries(WAF_ADDRESS_RANGES), 1071);
    assert.equal(EDGE_CNAME_RULES.reduce((sum, rule) => sum + rule.suffixes.length, 0), 103);
  });

  it('includes all four formerly omitted compound plugins as supported ports', () => {
    for (const plugin of REQUIRED_COMPOUND_PLUGINS) {
      const vendor = WAF_VENDOR_SIGNATURES[plugin];
      assert.ok(vendor, `${plugin} must be present`);
      assert.equal(vendor.port_status, 'supported');
      assert.ok(vendor.signatures.length >= 2);
      assert.equal(vendor.matcher.op, 'if');
    }
  });
});

describe('edge signature corpus structural safety', () => {
  it('references every signature from a valid decision tree instead of flattening it', () => {
    for (const [vendorKey, vendor] of Object.entries(WAF_VENDOR_SIGNATURES)) {
      assert.equal(vendor.port_status, 'supported', `${vendorKey} must fail generation otherwise`);
      const referenced = new Set();
      validateMatcher(vendor.matcher, vendor.signatures.length, referenced);
      assert.equal(referenced.size, vendor.signatures.length, `${vendorKey} has an omitted matcher call`);
    }
  });

  it('keeps every signature in the declared tier/signal vocabulary with compilable regexes', () => {
    for (const signature of corpusSignatures()) {
      assert.ok(TIERS.has(signature.tier), `unexpected tier ${signature.tier} on ${signature.vendor}`);
      assert.ok(SIGNALS.has(signature.signal), `unexpected signal ${signature.signal} on ${signature.vendor}`);
      if (signature.pattern !== undefined) assert.doesNotThrow(() => new RegExp(signature.pattern, 'i'));
      if (signature.signal === 'header') {
        assert.ok(signature.header_kind === 'exact' || signature.header_kind === 'regex');
        if (signature.header_kind === 'exact') {
          assert.equal(signature.header, signature.header.toLowerCase());
          assert.match(signature.header, /^[a-z0-9-]+$/);
        } else {
          assert.doesNotThrow(() => new RegExp(`^(?:${signature.header})$`, 'i'));
        }
      }
    }
  });

  it('contains response fingerprints but no reusable attack-payload signatures', () => {
    for (const signature of corpusSignatures()) {
      const pattern = String(signature.pattern ?? signature.value ?? '');
      for (const marker of PAYLOAD_LIKE) {
        assert.ok(!marker.test(pattern), `payload-like signature in ${signature.vendor}: ${pattern}`);
      }
    }
  });

  it('preserves cdncheck CNAME type explicitly on every provider rule', () => {
    assert.equal(EDGE_CNAME_RULES.length, 32);
    for (const rule of EDGE_CNAME_RULES) {
      assert.equal(rule.type, 'waf');
      assert.ok(rule.provider.length > 0);
      assert.ok(Array.isArray(rule.suffixes) && rule.suffixes.length > 0);
    }
    assert.ok(EDGE_CNAME_RULES.find((rule) => rule.provider === 'akamai')?.suffixes.includes('akamaiedge.net'));
    assert.ok(EDGE_CNAME_RULES.find((rule) => rule.provider === 'amazon')?.suffixes.includes('cloudfront.net'));
  });

  it('bounds exact, regex-name, and transient Set-Cookie extraction', () => {
    const serverValue = 'v'.repeat(500);
    const cookies = Array.from({ length: 20 }, (_, index) => `cookie${index}=${'s'.repeat(700)}; Path=/`);
    const requested = [];
    const headers = {
      get(name) {
        requested.push(name);
        if (name === 'server') return serverValue;
        if (name === 'x-custom-header') return 'not-in-corpus';
        return null;
      },
      getSetCookie: () => cookies,
      forEach(callback) {
        callback('shieldon.io', 'X-Protected-By');
        callback('not-in-corpus', 'X-Custom-Header');
      },
    };
    const entries = extractFingerprintHeaderEntries({ headers });
    assert.equal(entries.find((entry) => entry.name === 'server')?.value.length, 128);
    assert.deepEqual(entries.find((entry) => entry.name === 'x-protected-by'), {
      name: 'x-protected-by',
      value: 'shieldon.io',
    });
    const cookieEntry = entries.find((entry) => entry.name === 'set-cookie');
    assert.ok(cookieEntry, 'cookie matchers require bounded transient Set-Cookie evidence');
    assert.ok(cookieEntry.value.length <= 4096);
    assert.ok(cookieEntry.value.split(/,(?=\s*[^=;,\s]+\s*=)/).length <= 16);
    assert.ok(!requested.includes('x-custom-header'));
    assert.ok(!entries.some((entry) => entry.name === 'x-custom-header'));
  });
});

describe('strict AST generator behavior', () => {
  it('ports compound/helper logic and fails the entire generation on unsupported plugin syntax', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'astranull-edge-generator-'));
    const pluginDir = path.join(root, 'plugins');
    mkdirSync(pluginDir);
    try {
      writeFileSync(path.join(pluginDir, 'compound.py'), `
NAME = 'Compound Test (AstraNull)'

def is_waf(self):
    if self.matchHeader(('X-Test', 'yes')) and (helper(self) or self.matchCookie('^fallback=')):
        return True
    return False

def helper(self):
    if not self.matchContent('first'):
        return False
    if not self.matchContent('second'):
        return False
    return True
`);
      const parsed = extractWafPluginPrograms(pluginDir);
      assert.equal(parsed.pluginCount, 1);
      assert.equal(parsed.matcherCallCount, 4);
      assert.equal(parsed.vendors.compound.signatures.length, 4);
      assert.equal(parsed.vendors.compound.matcher.condition.op, 'and');
      assert.equal(parsed.vendors.compound.matcher.condition.args[1].op, 'or');

      writeFileSync(path.join(pluginDir, 'unsupported.py'), `
NAME = 'Unsupported Test (AstraNull)'

def is_waf(self):
    for value in ('x',):
        if self.matchContent(value):
            return True
    return False
`);
      assert.throws(
        () => extractWafPluginPrograms(pluginDir),
        /edge-signature generation failed: failed to port unsupported\.py:.*unsupported function statement For/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
