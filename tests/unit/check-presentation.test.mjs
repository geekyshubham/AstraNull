import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { CHECK_PRESENTATION_IDS, checkPresentation } from '../../src/lib/checkPresentation.mjs';
import { canonicalDefinitionDigest } from '../../src/lib/checkDefinitionVersion.mjs';
import { CHECK_DELIVERY_INVENTORY } from '../fixtures/check-delivery-coverage.mjs';

describe('presentation-only exact runtime catalog registry', () => {
  it('maps all and only the 275 final runtime IDs and audited receipt definitions', () => {
    const ids = CHECK_CATALOG.map((check) => check.check_id).sort();
    assert.equal(ids.length, 275);
    assert.deepEqual([...CHECK_PRESENTATION_IDS].sort(), ids);
    assert.deepEqual(CHECK_DELIVERY_INVENTORY.rows.map((row) => row.check_id).sort(), ids);
    for (const check of CHECK_CATALOG) {
      const before = canonicalDefinitionDigest(check);
      const entry = checkPresentation(check);
      assert.equal(entry, checkPresentation(check.check_id));
      assert.deepEqual(Object.keys(entry).sort(), ['name', 'purpose', 'limitations', 'next_step', 'mechanism'].sort());
      for (const value of Object.values(entry)) assert.ok(typeof value === 'string' && value.trim());
      assert.ok(entry.name.length <= 65, check.check_id);
      assert.ok(Object.isFrozen(entry));
      assert.equal(canonicalDefinitionDigest(check), before);
      const audit = CHECK_DELIVERY_INVENTORY.rows.find((row) => row.check_id === check.check_id);
      assert.deepEqual(audit.presentation, entry);
      assert.ok(audit.executor && audit.evaluation_order.length && audit.supported_conclusions.length && audit.capture_support);
      assert.equal(audit.audit_mapping_is_execution_proof, false);
      assert.deepEqual(audit.parameters, check.probe_profile ?? {});
      assert.deepEqual(audit.safety_bounds, check.safety_constraints);
      assert.deepEqual(audit.evidence_requirements, check.evidence_required ?? []);
    }
  });
  it('never trusts caller-supplied names and handles hostile/unknown IDs', () => {
    const expected = checkPresentation('waf.http_method_policy_marker.safe');
    assert.equal(checkPresentation({ check_id: 'waf.http_method_policy_marker.safe', name: 'Attack proved' }), expected);
    assert.equal(expected.name, 'HTTP-policy token observation');
    assert.match(expected.limitations, /No attack-method test/);
    for (const id of [null, undefined, '__proto__', 'constructor', 'not-a-check']) assert.equal(checkPresentation(id).name, 'Unknown check');
  });
  it('stays outside execution definitions and has no module/network dependencies', async () => {
    const catalog = await readFile(new URL('../../src/contracts/checks.mjs', import.meta.url), 'utf8');
    const presentation = await readFile(new URL('../../src/lib/checkPresentation.mjs', import.meta.url), 'utf8');
    assert.doesNotMatch(catalog, /checkPresentation/);
    assert.doesNotMatch(presentation, /\bimport\s|\bfetch\s*\(|node:/);
  });
  it('models actual-method E2 verdict capability separately from readiness and opaque-token setup', () => {
    const method = CHECK_DELIVERY_INVENTORY.rows.find((row) => row.check_id === 'waf.http_method_policy_enforced.safe');
    const token = CHECK_DELIVERY_INVENTORY.rows.find((row) => row.check_id === 'waf.http_method_policy_marker.safe');
    assert.equal(method.evidence_tier, 'E2');
    assert.equal(method.produces_verdict, true);
    assert.equal(method.readiness_eligible_kind, false);
    assert.equal(token.produces_verdict, false);
    assert.equal(token.readiness_eligible_kind, false);
    assert.match(checkPresentation(method.check_id).mechanism, /TRACE/);
    assert.doesNotMatch(checkPresentation(token.check_id).mechanism, /TRACE/);
  });
});
