import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { CONTROL_FAMILIES, MISSING_CONTROLS, MISSING_CONTROL_GROUPS, getMissingControl } from '../../src/contracts/missingControls/index.mjs';
import { MISSING_CONTROLS_WAF } from '../../src/contracts/missingControls/waf.mjs';
import { MISSING_CONTROLS_APPLICATION } from '../../src/contracts/missingControls/application.mjs';
import { MISSING_CONTROLS_NETWORK } from '../../src/contracts/missingControls/network.mjs';

const GENERIC = [
  /review edge protection/i,
  /submit a soc-gated/i,
  /\b(todo|tbd|lorem|placeholder|n\/a)\b/i,
  /review the recorded response/i,
];
const GROUP_FILES = { waf: MISSING_CONTROLS_WAF, application: MISSING_CONTROLS_APPLICATION, network: MISSING_CONTROLS_NETWORK };

describe('missing-control catalog', () => {
  it('has exactly one entry for every catalog check and none for unknown checks', () => {
    const catalogIds = CHECK_CATALOG.map((check) => check.check_id).sort();
    assert.deepEqual(Object.keys(MISSING_CONTROLS).sort(), catalogIds);
  });

  it('places each entry in the group file that owns its vector family', () => {
    for (const check of CHECK_CATALOG) {
      const [group] = Object.entries(MISSING_CONTROL_GROUPS).find(([, families]) => families.includes(check.vector_family)) ?? [];
      assert.ok(group, `${check.check_id} vector family ${check.vector_family} has no owning group`);
      assert.ok(GROUP_FILES[group][check.check_id], `${check.check_id} must be defined in ${group}.mjs`);
    }
  });

  for (const check of CHECK_CATALOG) {
    it(`${check.check_id} names a specific missing control and required policy`, () => {
      const entry = getMissingControl(check.check_id);
      assert.ok(entry, 'entry required');
      assert.ok(CONTROL_FAMILIES[entry.control_family], `unknown control_family ${entry.control_family}`);
      for (const field of ['missing_control', 'required_policy']) {
        const text = entry[field];
        assert.equal(typeof text, 'string', `${field} must be a string`);
        assert.ok(text.trim().length >= 40 && text.length <= 400, `${field} must be 40-400 characters`);
        assert.equal(text, text.trim());
        assert.ok(/[.]$/.test(text), `${field} must be a complete sentence`);
        for (const pattern of GENERIC) assert.doesNotMatch(text, pattern, `${field} is generic`);
      }
      assert.notEqual(entry.missing_control, entry.required_policy);
      assert.deepEqual(Object.keys(entry).sort(), ['check_id', 'control_family', 'missing_control', 'required_policy']);
    });
  }
});
