import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { plainEfficacySentence } from '../../apps/web/react/src/lib/domain-checks.mjs';

const base = { layer: 'waf', status: 'unknown', basis: 'verdicts', passed: 0, tested: 0, failed: 0, ruleCategories: 0, inconclusive: 0, ignored: 0 };

describe('plainEfficacySentence', () => {
  it('names the next step when nothing is measured', () => {
    assert.equal(plainEfficacySentence(base), 'Not tested yet. Run the WAF checks to find out.');
    assert.equal(plainEfficacySentence({ ...base, layer: 'cdn', status: 'absent' }), 'No CDN was detected in front of this domain.');
  });

  it('counts the checks still needed instead of quoting scoring rules', () => {
    assert.equal(plainEfficacySentence({ ...base, status: 'insufficient', tested: 2 }), 'Not enough results yet. Run 1 more WAF check to find out.');
    assert.equal(plainEfficacySentence({ ...base, status: 'insufficient', tested: 4, ruleCategories: 1 }), 'Not enough results yet. Run WAF checks from another rule category to find out.');
  });

  it('never reads a bypassable or failing layer as protecting', () => {
    assert.match(plainEfficacySentence({ ...base, status: 'bypassable', passed: 5, tested: 5 }), /origin answers directly/);
    assert.equal(plainEfficacySentence({ ...base, status: 'failing', passed: 3, tested: 5, failed: 2 }), '2 of 5 recent checks got through.');
    assert.equal(plainEfficacySentence({ ...base, status: 'protecting', passed: 4, tested: 4 }), 'Held on 4 of 4 recent checks.');
  });

  it('keeps the fingerprint scan as context only', () => {
    assert.match(plainEfficacySentence({ ...base, status: 'insufficient', basis: 'fingerprint_markers', passed: 3, tested: 4 }), /Only the fingerprint scan ran \(3 of 4 markers blocked\)/);
  });
});
