import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  GOVERNED_SCENARIO_FAMILIES,
  buildGovernedScenarioReview,
  normalizeGovernedDeliveryPatterns,
  normalizeGovernedScenarioFamilies,
  scenarioFamiliesCoverRequested,
} from '../../src/contracts/governedScenarios.mjs';
import { DELIVERY_PATTERN_LABELS } from '../../src/contracts/resourceExhaustionTaxonomy.mjs';
import { EXHAUSTED_RESOURCE_FAMILIES } from '../../src/contracts/resourceExhaustionTaxonomy.mjs';

describe('governed scenario taxonomy (SOC-011 / DET-022)', () => {
  it('defines governed families bound to exhausted resources and limit fields', () => {
    const familyIds = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));
    assert.ok(GOVERNED_SCENARIO_FAMILIES.length >= 25);
    for (const family of GOVERNED_SCENARIO_FAMILIES) {
      assert.ok(family.id, 'family id required');
      assert.ok(family.label, `${family.id} label required`);
      assert.ok(familyIds.has(family.exhausted_resource), `${family.id} exhausted_resource`);
      assert.ok(family.limit_field.startsWith('max_'), `${family.id} limit_field`);
      assert.ok(Array.isArray(family.delivery_patterns) && family.delivery_patterns.length > 0, `${family.id} delivery_patterns`);
    }
    const ids = GOVERNED_SCENARIO_FAMILIES.map((f) => f.id);
    for (const required of ['udp_flood', 'syn_flood', 'http_get_flood', 'dns_query_flood', 'carpet_bombing', 'rapid_reset_validation']) {
      assert.ok(ids.includes(required), `missing governed family ${required}`);
    }
  });

  it('normalizes requested families and rejects unknown ones', () => {
    const ok = normalizeGovernedScenarioFamilies(['udp_flood', 'dns_query_flood', 'udp_flood']);
    assert.equal(ok.ok, true);
    assert.deepEqual(ok.value, ['udp_flood', 'dns_query_flood']);
    const bad = normalizeGovernedScenarioFamilies(['udp_flood', 'totally_made_up']);
    assert.equal(bad.ok, false);
    assert.deepEqual(bad.unknown, ['totally_made_up']);
    assert.equal(normalizeGovernedScenarioFamilies([]).ok, false);
    assert.equal(normalizeGovernedScenarioFamilies('udp_flood').ok, false);
  });

  it('normalizes delivery patterns against the taxonomy labels', () => {
    const ok = normalizeGovernedDeliveryPatterns(['direct', 'pulse_wave']);
    assert.equal(ok.ok, true);
    assert.deepEqual(ok.value, ['direct', 'pulse_wave']);
    const bad = normalizeGovernedDeliveryPatterns(['not_a_pattern']);
    assert.equal(bad.ok, false);
    assert.deepEqual(bad.unknown, ['not_a_pattern']);
    assert.deepEqual(normalizeGovernedDeliveryPatterns(null).value, []);
  });

  it('binds authorization packs to requested families (SOC-011)', () => {
    assert.deepEqual(
      scenarioFamiliesCoverRequested(['udp_flood', 'dns_query_flood'], ['udp_flood', 'dns_query_flood']),
      { ok: true, uncovered: [] },
    );
    const partial = scenarioFamiliesCoverRequested(['udp_flood', 'http_post_flood'], ['udp_flood']);
    assert.equal(partial.ok, false);
    assert.deepEqual(partial.uncovered, ['http_post_flood']);
  });

  it('builds a SOC review summary with per-scenario governance metadata', () => {
    const review = buildGovernedScenarioReview(['syn_flood']);
    assert.equal(review.ok, true);
    assert.equal(review.scenarios.length, 1);
    const scenario = review.scenarios[0];
    assert.equal(scenario.scenario_family, 'syn_flood');
    assert.equal(scenario.exhausted_resource, 'state_exhaustion');
    assert.equal(scenario.required_limit_field, 'max_cps');
    assert.ok(scenario.delivery_patterns.every((p) => DELIVERY_PATTERN_LABELS.includes(p)));
    const bad = buildGovernedScenarioReview(['made_up_family']);
    assert.equal(bad.ok, false);
    assert.deepEqual(bad.unknown, ['made_up_family']);
  });
});
