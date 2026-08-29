import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ATTACK_VECTOR_REGISTRY,
  EXHAUSTED_RESOURCE_FAMILIES,
  FAMILY_BUILD_SPECS,
  RESOURCE_EXHAUSTION_TASKS,
  summarizeCoverage,
} from '../../src/contracts/resourceExhaustionTaxonomy.mjs';
import { validateResourceExhaustionTaxonomy } from '../../scripts/validate-resource-exhaustion-taxonomy.mjs';

describe('resource-exhaustion taxonomy', () => {
  it('defines twelve exhausted-resource families', () => {
    assert.equal(EXHAUSTED_RESOURCE_FAMILIES.length, 12);
    const ids = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));
    assert.ok(ids.has('volumetric'));
    assert.ok(ids.has('dns_exhaustion'));
    assert.ok(ids.has('delivery_pattern'));
  });

  it('registers major attack classes from the master taxonomy', () => {
    const names = new Set(ATTACK_VECTOR_REGISTRY.map((e) => e.name));
    assert.ok(names.has('UDP flood'));
    assert.ok(names.has('HTTP/2 Rapid Reset'));
    assert.ok(names.has('DNS laundering'));
    assert.ok(names.has('Carpet bombing'));
    assert.ok(names.has('HTTP/2 MadeYouReset'));
  });

  it('tracks backlog tasks DET-016 through DET-026 and SOC-011', () => {
    const ids = new Set(RESOURCE_EXHAUSTION_TASKS.map((t) => t.id));
    for (const id of ['DET-016', 'DET-017', 'DET-018', 'DET-019', 'DET-020', 'DET-021', 'DET-022', 'DET-023', 'DET-024', 'DET-025', 'DET-026', 'SOC-011']) {
      assert.ok(ids.has(id), `missing task ${id}`);
    }
  });

  it('defines build specs for all twelve resource families', () => {
    assert.equal(FAMILY_BUILD_SPECS.length, EXHAUSTED_RESOURCE_FAMILIES.length);
    for (const family of EXHAUSTED_RESOURCE_FAMILIES) {
      const spec = FAMILY_BUILD_SPECS.find((s) => s.id === family.id);
      assert.ok(spec, `missing FAMILY_BUILD_SPECS for ${family.id}`);
      assert.ok((spec.build_checks ?? []).length > 0, `${family.id} needs build_checks`);
    }
  });

  it('validator passes registry ↔ catalog cross-check', () => {
    const result = validateResourceExhaustionTaxonomy();
    assert.equal(result.ok, true, result.errors.join('; '));
    assert.ok(result.taxonomy.attack_vectors >= 140);
    assert.ok(result.taxonomy.coverage.pending > 0, 'expected pending backlog');
  });

  it('maps every catalog check to ATT, ND, or WAF registry', () => {
    const result = validateResourceExhaustionTaxonomy();
    const orphanErrors = result.errors.filter((e) => e.includes('orphan catalog'));
    assert.equal(orphanErrors.length, 0, orphanErrors.join('; '));
  });

  it('registers extended attack and exposure classes (ATT-126+)', () => {
    const ids = new Set(ATTACK_VECTOR_REGISTRY.map((e) => e.id));
    for (const id of ['ATT-126', 'ATT-147', 'ATT-163', 'ATT-171', 'ATT-176']) {
      assert.ok(ids.has(id), `missing ${id}`);
    }
  });

  it('reports honest partial coverage (most vectors not fully implemented)', () => {
    const summary = summarizeCoverage();
    assert.ok(summary.pending > summary.implemented, 'pending should exceed fully implemented');
    assert.ok(summary.partial > 0);
  });
});
