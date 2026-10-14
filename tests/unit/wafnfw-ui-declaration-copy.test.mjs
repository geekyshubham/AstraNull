import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { RULE_COVERAGE_CATEGORIES, catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import {
  REQUIRED_DECLARATION_COPY,
  UNKNOWN_DECLARATION_COPY,
  controlsHref,
  inlineDeclarationLabel,
  requiredDeclarationCopy,
  requiredDeclarationSentence,
} from '../../apps/web/react/src/lib/control-declarations.mjs';
import { normalizeRuleCoverage } from '../../apps/web/react/src/lib/rule-coverage.mjs';

const MACHINE_TOKEN = /\b[a-z]+(?:[._][a-z0-9]+)+\b/;

describe('required-declaration copy', () => {
  it('gives every key the server can list in rule coverage its own plain copy', () => {
    const keys = new Set(RULE_COVERAGE_CATEGORIES.flatMap((category) => category.required_declarations ?? []));
    for (const category of catalogRuleCoverage().categories) for (const key of category.required_declarations) keys.add(key);
    assert.ok(keys.has('origin_binding'));
    for (const key of keys) {
      assert.ok(Object.hasOwn(REQUIRED_DECLARATION_COPY, key), `no copy for ${key}`);
      const copy = requiredDeclarationCopy(key);
      assert.notEqual(copy, UNKNOWN_DECLARATION_COPY);
      assert.doesNotMatch(copy.label, MACHINE_TOKEN, key);
      assert.ok(copy.cta && copy.section, `no call to action for ${key}`);
    }
  });

  it('links origin_binding to Origin relations on the Overview tab', () => {
    const copy = requiredDeclarationCopy('origin_binding');
    assert.equal(copy.label, 'One verified origin binding');
    assert.equal(copy.cta, 'Open Origin relations');
    assert.equal(controlsHref('tgt_1', copy.section), '#target-detail?id=tgt_1&tab=overview&section=origin-relations');
  });

  it('falls back to generic copy for unknown or empty keys and never echoes the key', () => {
    for (const key of ['future_declaration_key', 'waf.new_thing', '', null, undefined, 42, 'toString', '__proto__']) {
      assert.equal(requiredDeclarationCopy(key), UNKNOWN_DECLARATION_COPY);
    }
    const sentence = requiredDeclarationSentence(['network_policy', 'future_declaration_key', 'other_unknown_key']);
    assert.equal(sentence, 'network policy and an additional target setting');
    assert.doesNotMatch(sentence, /future_declaration_key|other_unknown_key/);
  });

  it('joins labels for use mid-sentence and keeps acronyms', () => {
    assert.equal(requiredDeclarationSentence(['origin.lockdown_expected', 'origin_binding']), 'origin lockdown and one verified origin binding');
    assert.equal(requiredDeclarationSentence(['canary_sink']), 'canary sink URL');
    assert.equal(requiredDeclarationSentence(['network_policy', 'connection_limits', 'perspectives']), 'network policy, connection limits and probe perspectives');
    assert.equal(requiredDeclarationSentence([]), '');
    assert.equal(inlineDeclarationLabel('URL target'), 'URL target');
  });
});

describe('rule-coverage view model', () => {
  it('renders no raw declaration key in the catalog sentence', () => {
    const model = normalizeRuleCoverage(catalogRuleCoverage());
    const origin = model.categories.find((category) => category.id === 'origin_lockdown');
    assert.ok(origin);
    assert.equal(origin.requiredSentence, 'origin lockdown and one verified origin binding');
    for (const category of model.categories) assert.doesNotMatch(category.requiredSentence, MACHINE_TOKEN, category.id);
  });

  it('keeps unknown missing keys out of the CTAs but still names them in plain words', () => {
    const model = normalizeRuleCoverage({
      categories: [{ id: 'x', layer: 'nfw', name: 'X', status: 'needs_declaration', required_declarations: ['origin_binding', 'future_key'], missing_declarations: ['origin_binding', 'future_key'] }],
    });
    const [category] = model.categories;
    assert.deepEqual(category.ctas.map((cta) => [cta.key, cta.section]), [['origin_binding', 'origin_relations']]);
    assert.equal(category.missingWithoutCta, 'an additional target setting');
  });
});
