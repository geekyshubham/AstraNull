import assert from 'node:assert/strict';
import { test } from 'node:test';
import { presentProductDetectionEvidence } from '../../src/lib/productDetectionEvidence.mjs';
import { presentTargetEdgeDetection } from '../../src/lib/edgeDetectionPresenter.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { edgeEvidenceSignals } from '../../apps/web/react/src/lib/domain-checks.mjs';

test('retained detection evidence uses product names without mutating stored proof', () => {
  const stored = {
    wafw00f: { detected: true, firewall: 'Cloudflare', corpus: 'wafw00f' },
    cdncheck: { matched: true, provider: 'cloudflare', item_type: 'cdn', source: 'ip' },
    fields: ['edge_signature.wafw00f.all_matches'],
  };
  const original = JSON.stringify(stored);
  const publicEvidence = presentProductDetectionEvidence(stored);
  assert.equal(JSON.stringify(stored), original);
  assert.equal(/wafw00f|cdncheck/i.test(JSON.stringify(publicEvidence)), false);
  assert.equal(publicEvidence.waf_fingerprint.firewall, 'Cloudflare');
  assert.equal(publicEvidence.edge_classifier.provider, 'cloudflare');
  assert.deepEqual(publicEvidence.fields, ['edge_signature.waf_fingerprint.all_matches']);
  const presented = presentTargetEdgeDetection({ status: 'detected', evidence_json: stored });
  assert.equal(/wafw00f|cdncheck/i.test(JSON.stringify(presented)), false);
  const { facts } = edgeEvidenceSignals(presented);
  assert.ok(facts.some((fact) => fact.label === 'AstraNull WAF fingerprint'));
  assert.ok(facts.some((fact) => fact.label === 'AstraNull edge classifier'));
  assert.equal(/wafw00f|cdncheck/i.test(JSON.stringify(facts)), false);
});

test('canonical detection fields take precedence over legacy aliases', () => {
  for (const value of [
    { wafw00f: { detected: true }, waf_fingerprint: { detected: false } },
    { waf_fingerprint: { detected: false }, wafw00f: { detected: true } },
  ]) assert.deepEqual(presentProductDetectionEvidence(value), { waf_fingerprint: { detected: false } });
});

test('customer check descriptions and verdict logic use product terminology', () => {
  for (const check of CHECK_CATALOG) {
    assert.equal(/wafw00f|cdncheck/i.test(JSON.stringify({ name: check.name, description: check.description, logic: check.verdict_logic })), false, check.check_id);
  }
});
