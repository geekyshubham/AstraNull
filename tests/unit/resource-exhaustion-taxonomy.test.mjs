import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ATTACK_VECTOR_REGISTRY,
  ATTACK_SURFACE_DOMAINS,
  COVERAGE_STATUS_SEMANTICS,
  EXHAUSTED_RESOURCE_FAMILIES,
  FAMILY_BUILD_SPECS,
  NON_DDOS_AVAILABILITY_THREATS,
  OUT_OF_SCOPE_VECTORS,
  RESOURCE_EXHAUSTION_TASKS,
  WAF_VULNERABILITY_REGISTRY,
  summarizeCoverage,
} from '../../src/contracts/resourceExhaustionTaxonomy.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { evidenceTierForCheck } from '../../src/lib/readinessVerdicts.mjs';
import { evidenceTierForTaxonomyCheckId } from '../../src/lib/probeEvidenceTiers.mjs';
import {
  WORKER_EXECUTED_KIND_BY_DECLARED_KIND,
  validateDeclaredProbeKinds,
  validateResourceExhaustionTaxonomy,
} from '../../scripts/validate-resource-exhaustion-taxonomy.mjs';

describe('resource-exhaustion taxonomy', () => {
  it('defines DDoS and non-DDoS exhausted-resource families', () => {
    assert.equal(EXHAUSTED_RESOURCE_FAMILIES.length, 17);
    const ids = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));
    assert.ok(ids.has('volumetric'));
    assert.ok(ids.has('dns_exhaustion'));
    assert.ok(ids.has('delivery_pattern'));
    for (const id of ['integrity_attack', 'access_control', 'data_exposure', 'automation_abuse', 'ai_agentic']) {
      const family = EXHAUSTED_RESOURCE_FAMILIES.find((entry) => entry.id === id);
      assert.equal(family?.scored_for_ddos_readiness, false, id);
    }
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

  it('defines build specs for all DDoS-scored resource families', () => {
    const scoredFamilies = EXHAUSTED_RESOURCE_FAMILIES.filter((family) => family.scored_for_ddos_readiness);
    assert.equal(FAMILY_BUILD_SPECS.length, scoredFamilies.length);
    for (const family of scoredFamilies) {
      const spec = FAMILY_BUILD_SPECS.find((s) => s.id === family.id);
      assert.ok(spec, `missing FAMILY_BUILD_SPECS for ${family.id}`);
      assert.ok((spec.has_today ?? []).length > 0, `${family.id} needs delivered has_today checks`);
    }
  });

  it('validator passes registry ↔ catalog cross-check with no unclaimed or duplicate catalog IDs', (t) => {
    const result = validateResourceExhaustionTaxonomy();
    assert.equal(result.ok, true, result.errors.join('; '));
    assert.ok(result.taxonomy.attack_vectors >= 140);
    assert.equal(result.catalog_unclaimed_count, 0, result.catalog_unclaimed_ids.join(', '));
    assert.deepEqual(result.catalog_unclaimed_ids, []);
    const duplicateClaimErrors = result.errors.filter((error) => error.includes('duplicate registry claims'));
    assert.equal(duplicateClaimErrors.length, 0, duplicateClaimErrors.join('; '));
    assert.equal(
      result.taxonomy.coverage.implemented
        + result.taxonomy.coverage.partial
        + result.taxonomy.coverage.soc_only
        + result.taxonomy.coverage.pending,
      result.taxonomy.attack_vectors,
    );
    t.diagnostic(`legitimate pending attack-vector entries: ${result.taxonomy.coverage.pending}`);
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

  it('reports the full honest mixed-coverage distribution, including legitimate pending entries', (t) => {
    const summary = summarizeCoverage();
    assert.ok(summary.implemented > 0, 'dedicated semantic probe families remain implemented');
    assert.ok(summary.partial > summary.implemented, 'metadata/liveness/posture coverage remains partial');
    assert.ok(summary.soc_only > 0, 'governed-only vectors remain SOC-only');
    assert.ok(Number.isInteger(summary.pending) && summary.pending >= 0);
    assert.equal(
      summary.implemented + summary.partial + summary.soc_only + summary.pending,
      summary.total,
    );
    t.diagnostic(`coverage distribution: ${JSON.stringify(summary)}`);
  });

  it('derives all four check evidence-tier branches', () => {
    assert.equal(evidenceTierForCheck({}), 'E4');
    assert.equal(evidenceTierForCheck({ probe_profile: { kind: 'metadata_marker' } }), 'E1');
    assert.equal(evidenceTierForCheck({ probe_profile: { kind: 'http_head' } }), 'E2');
    assert.equal(evidenceTierForCheck({ probe_profile: { kind: 'rate_limit_sequence' } }), 'E3');
  });

  it('derives status from the best mapped evidence tier', () => {
    for (const id of ['ATT-017', 'ATT-018', 'ATT-019', 'ATT-020', 'ATT-115']) {
      assert.equal(
        ATTACK_VECTOR_REGISTRY.find((entry) => entry.id === id)?.coverage_status,
        'implemented',
        id,
      );
    }
    for (const id of ['ATT-026', 'ATT-134', 'ATT-165']) {
      assert.equal(ATTACK_VECTOR_REGISTRY.find((entry) => entry.id === id)?.coverage_status, 'partial', id);
    }
    for (const id of ['ATT-090', 'ATT-093', 'ATT-096', 'ATT-099', 'ATT-173']) {
      assert.equal(
        ATTACK_VECTOR_REGISTRY.find((entry) => entry.id === id)?.coverage_status,
        'soc_only',
        id,
      );
    }
  });

  it('enforces coverage status semantics against mapped probe implementations', () => {
    assert.match(COVERAGE_STATUS_SEMANTICS.implemented, /live semantic|inline/);
    assert.match(COVERAGE_STATUS_SEMANTICS.partial, /metadata|liveness/);
    assert.match(COVERAGE_STATUS_SEMANTICS.soc_only, /SOC-gated/);

    for (const entry of ATTACK_VECTOR_REGISTRY) {
      const checks = (entry.check_ids ?? []).map(getCheckById).filter(Boolean);
      const priority = { E0: 0, E1: 1, E4: 2, E2: 3, E3: 4 };
      const tier = checks.reduce((best, check) => (
        priority[evidenceTierForCheck(check)] > priority[best] ? evidenceTierForCheck(check) : best
      ), 'E0');
      assert.equal(entry.evidence_tier, tier, entry.id);
      assert.equal(
        entry.coverage_status,
        tier === 'E3' ? 'implemented' : tier === 'E1' || tier === 'E2' ? 'partial' : tier === 'E4' ? 'soc_only' : 'pending',
        entry.id,
      );
    }
    for (const entry of WAF_VULNERABILITY_REGISTRY) {
      const hasMappedSocCheck = (entry.check_ids ?? [])
        .some((checkId) => checkId.endsWith('.soc') && getCheckById(checkId));
      assert.equal(entry.evidence_tier, hasMappedSocCheck ? 'E4' : 'E0', entry.id);
      assert.equal(entry.coverage_status, hasMappedSocCheck ? 'soc_only' : 'pending', entry.id);
    }
    for (const entry of NON_DDOS_AVAILABILITY_THREATS) assert.equal(entry.evidence_tier, 'E5', entry.id);
  });

  it('defines all attack-surface domains and assigns every attack vector', () => {
    assert.deepEqual(ATTACK_SURFACE_DOMAINS.map((domain) => domain.id), [
      'A1a', 'A1b', 'A1c', 'A1d', 'A2', 'A3', 'A4a', 'A4b', 'A5', 'A7', 'A8',
    ]);
    const ids = new Set(ATTACK_SURFACE_DOMAINS.map((domain) => domain.id));
    for (const entry of ATTACK_VECTOR_REGISTRY) assert.ok(ids.has(entry.domain), entry.id);
    for (const id of ['A1b', 'A1c', 'A1d']) {
      assert.equal(ATTACK_SURFACE_DOMAINS.find((domain) => domain.id === id)?.probe_reachable, false);
    }
  });

  it('keeps catalog vector claims unique and well formed across registries', () => {
    const seen = new Map();
    for (const entry of [
      ...ATTACK_VECTOR_REGISTRY,
      ...WAF_VULNERABILITY_REGISTRY,
      ...NON_DDOS_AVAILABILITY_THREATS,
    ]) {
      assert.ok(Array.isArray(entry.catalog_vector_ids), entry.id);
      for (const catalogId of entry.catalog_vector_ids) {
        assert.match(catalogId, /^(NET|AMP|APP|WAF|EVA)-\d{3}$/);
        assert.equal(seen.has(catalogId), false, `${catalogId}: ${seen.get(catalogId)} and ${entry.id}`);
        seen.set(catalogId, entry.id);
      }
    }
  });

  it('declares exactly 41 outside-in exclusions with auditable reason codes', () => {
    const expectedByReason = {
      requires_l2_adjacency: [
        'NET-030', 'NET-031', 'NET-032', 'NET-033', 'NET-034', 'NET-091', 'NET-092',
        'NET-093', 'NET-094', 'NET-095', 'NET-096', 'NET-097', 'NET-147', 'NET-148',
        'NET-149', 'NET-150', 'NET-151', 'NET-152', 'NET-153', 'NET-154', 'NET-155',
      ],
      requires_routing_peer_session: [
        'NET-042', 'NET-043', 'NET-044', 'NET-125', 'NET-156', 'NET-157',
      ],
      requires_rf_proximity: [
        'NET-169', 'NET-170', 'NET-171', 'NET-172', 'NET-173', 'NET-174', 'NET-175',
        'NET-176', 'NET-177',
      ],
      requires_mobile_core_interface: [
        'NET-158', 'NET-159', 'NET-178', 'NET-179', 'NET-180',
      ],
    };
    const actualByReason = Object.fromEntries(
      OUT_OF_SCOPE_VECTORS.map((entry) => [entry.reason, [...entry.catalog_vector_ids].sort()]),
    );
    assert.equal(OUT_OF_SCOPE_VECTORS.flatMap((entry) => entry.catalog_vector_ids).length, 41);
    assert.deepEqual(actualByReason, expectedByReason);
  });

  it('keeps the standalone taxonomy evidence index aligned with live check probe profiles', () => {
    for (const entry of [...ATTACK_VECTOR_REGISTRY, ...WAF_VULNERABILITY_REGISTRY]) {
      for (const checkId of entry.check_ids ?? []) {
        assert.equal(
          evidenceTierForTaxonomyCheckId(checkId),
          evidenceTierForCheck(getCheckById(checkId)),
          checkId,
        );
      }
    }
  });

  it('reports a declared-kind error for a deliberately stale worker route', () => {
    const fixture = [{ check_id: 'fixture.dns.safe', probe_profile: { kind: 'dns_wire_query' } }];
    const routing = { ...WORKER_EXECUTED_KIND_BY_DECLARED_KIND, dns_wire_query: 'http_head' };
    assert.deepEqual(
      validateDeclaredProbeKinds(fixture, routing),
      ['fixture.dns.safe: declared probe kind dns_wire_query executes as http_head'],
    );
  });
});
