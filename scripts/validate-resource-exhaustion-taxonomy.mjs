#!/usr/bin/env node
/**
 * Validates resource-exhaustion taxonomy registry against CHECK_CATALOG.
 * Emits metadata-only coverage summary; does not run attack traffic.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CHECK_CATALOG, getCheckById } from '../src/contracts/checks.mjs';
import {
  ATTACK_VECTOR_REGISTRY,
  EXHAUSTED_RESOURCE_FAMILIES,
  FAMILY_BUILD_SPECS,
  NON_DDOS_AVAILABILITY_THREATS,
  RESOURCE_EXHAUSTION_TASKS,
  WAF_VULNERABILITY_REGISTRY,
  buildResourceExhaustionCheckMetadata,
  collectMappedCheckIds,
  getAttackIdsByFamily,
  summarizeCoverage,
} from '../src/contracts/resourceExhaustionTaxonomy.mjs';

const DEFAULT_OUT = 'output/resource-exhaustion-taxonomy-validation.json';

function parseArgs(argv) {
  let out = DEFAULT_OUT;
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--out' && argv[i + 1]) {
      out = argv[i + 1];
      i += 1;
    }
  }
  return { out };
}

export function validateResourceExhaustionTaxonomy() {
  const errors = [];
  const warnings = [];
  const catalogIds = new Set(CHECK_CATALOG.map((c) => c.check_id));

  for (const family of EXHAUSTED_RESOURCE_FAMILIES) {
    if (!family.id || !family.label) {
      errors.push(`resource family missing id/label: ${JSON.stringify(family)}`);
    }
  }

  const taskIds = new Set(RESOURCE_EXHAUSTION_TASKS.map((t) => t.id));
  const familyIds = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));

  for (const spec of FAMILY_BUILD_SPECS) {
    if (!familyIds.has(spec.id)) {
      errors.push(`FAMILY_BUILD_SPECS unknown family id: ${spec.id}`);
    }
    for (const checkId of spec.has_today ?? []) {
      if (!catalogIds.has(checkId)) {
        errors.push(`FAMILY_BUILD_SPECS ${spec.id}: unknown has_today check_id ${checkId}`);
      }
    }
  }
  for (const familyId of familyIds) {
    if (!FAMILY_BUILD_SPECS.some((s) => s.id === familyId)) {
      errors.push(`missing FAMILY_BUILD_SPECS for family ${familyId}`);
    }
  }

  const attackIds = new Set(ATTACK_VECTOR_REGISTRY.map((e) => e.id));
  for (const spec of FAMILY_BUILD_SPECS) {
    const expected = new Set(getAttackIdsByFamily(spec.id));
    for (const listed of spec.registry_attack_ids ?? []) {
      if (!attackIds.has(listed)) {
        errors.push(`FAMILY_BUILD_SPECS ${spec.id}: unknown registry_attack_ids entry ${listed}`);
      }
      if (!expected.has(listed)) {
        errors.push(`FAMILY_BUILD_SPECS ${spec.id}: ${listed} not in ATTACK_VECTOR_REGISTRY for family ${spec.id}`);
      }
    }
    for (const id of expected) {
      if (!(spec.registry_attack_ids ?? []).includes(id)) {
        errors.push(`FAMILY_BUILD_SPECS ${spec.id}: missing registry_attack_ids entry for ${id}`);
      }
    }
  }

  const mappedCheckIds = collectMappedCheckIds();
  const orphanCatalogChecks = [...catalogIds]
    .filter((checkId) => !mappedCheckIds.has(checkId))
    .sort();
  for (const checkId of orphanCatalogChecks) {
    errors.push(`orphan catalog check_id not mapped to ATT/ND/WV registry: ${checkId}`);
  }

  // DET-016: every catalog entry must carry metadata exactly derived from the registries.
  const familyIdSet = new Set(EXHAUSTED_RESOURCE_FAMILIES.map((f) => f.id));
  const expectedMetadata = buildResourceExhaustionCheckMetadata();
  const metadataFields = [
    'attack_vector_ids',
    'delivery_patterns',
    'waf_vulnerability_ids',
    'non_ddos_threat_ids',
  ];
  const emptyMetadata = {
    exhausted_resource: null,
    attack_vector_ids: [],
    delivery_patterns: [],
    waf_vulnerability_ids: [],
    non_ddos_threat_ids: [],
  };
  const catalogWithoutMetadata = [];
  for (const check of CHECK_CATALOG) {
    const hasMetadata = 'exhausted_resource' in check
      && metadataFields.every((field) => Array.isArray(check[field]));
    if (!hasMetadata) {
      catalogWithoutMetadata.push(check.check_id);
      continue;
    }
    if (check.exhausted_resource !== null && !familyIdSet.has(check.exhausted_resource)) {
      errors.push(`${check.check_id}: exhausted_resource ${check.exhausted_resource} is not a known family id`);
    }
    const expected = expectedMetadata.get(check.check_id) ?? emptyMetadata;
    if (check.exhausted_resource !== expected.exhausted_resource) {
      errors.push(`${check.check_id}: exhausted_resource does not match registry-derived metadata`);
    }
    for (const field of metadataFields) {
      if (JSON.stringify(check[field]) !== JSON.stringify(expected[field])) {
        errors.push(`${check.check_id}: ${field} does not match registry-derived metadata`);
      }
    }
    if (
      check.exhausted_resource === null
      && check.waf_vulnerability_ids.length === 0
      && check.non_ddos_threat_ids.length === 0
    ) {
      errors.push(`${check.check_id}: exhausted_resource is null without WAF or non-DDoS threat mapping`);
    }
  }
  if (catalogWithoutMetadata.length) {
    errors.push(`${catalogWithoutMetadata.length} catalog checks missing resource-exhaustion metadata (run applyResourceExhaustionMetadata): ${catalogWithoutMetadata.slice(0, 10).join(', ')}`);
  }

  for (const threat of NON_DDOS_AVAILABILITY_THREATS) {
    for (const checkId of threat.check_ids ?? []) {
      if (!catalogIds.has(checkId)) {
        errors.push(`${threat.id}: unknown check_id ${checkId}`);
      }
    }
  }

  for (const entry of ATTACK_VECTOR_REGISTRY) {
    if (!entry.id || !entry.name || !entry.exhausted_resource || !entry.coverage_status || !entry.task_id) {
      errors.push(`attack entry missing required fields: ${entry.id ?? '(no id)'}`);
      continue;
    }
    if (!taskIds.has(entry.task_id) && !entry.task_id.startsWith('DET-00') && !entry.task_id.startsWith('SOC-')) {
      warnings.push(`${entry.id}: task_id ${entry.task_id} not in RESOURCE_EXHAUSTION_TASKS`);
    }
    if (entry.coverage_status === 'pending' && entry.check_ids?.length) {
      errors.push(`${entry.id}: pending entry must not list check_ids`);
    }
    if (entry.coverage_status !== 'pending' && (!entry.check_ids || entry.check_ids.length === 0)) {
      errors.push(`${entry.id}: ${entry.coverage_status} entry must list at least one check_id`);
    }
    for (const checkId of entry.check_ids ?? []) {
      if (!catalogIds.has(checkId)) {
        errors.push(`${entry.id}: unknown check_id ${checkId}`);
      } else if (!getCheckById(checkId)) {
        errors.push(`${entry.id}: getCheckById failed for ${checkId}`);
      }
    }
  }

  const summary = summarizeCoverage();
  const pendingEntries = ATTACK_VECTOR_REGISTRY.filter((e) => e.coverage_status === 'pending');
  const implementedEntries = ATTACK_VECTOR_REGISTRY.filter((e) => e.coverage_status === 'implemented');
  if (pendingEntries.length > 0) {
    errors.push(`pending attack vectors remain: ${pendingEntries.map((entry) => entry.id).join(', ')}`);
  }

  const ddosCatalogChecks = CHECK_CATALOG.filter((check) => check.exhausted_resource != null);
  const nonDdosOnlyChecks = CHECK_CATALOG.filter((check) => (
    check.exhausted_resource == null
    && check.non_ddos_threat_ids.length > 0
    && check.waf_vulnerability_ids.length === 0
  ));
  const wafOnlyChecks = CHECK_CATALOG.filter((check) => (
    check.exhausted_resource == null
    && check.waf_vulnerability_ids.length > 0
    && check.non_ddos_threat_ids.length === 0
  ));
  const mixedUnscoredChecks = CHECK_CATALOG.filter((check) => (
    check.exhausted_resource == null
    && check.waf_vulnerability_ids.length > 0
    && check.non_ddos_threat_ids.length > 0
  ));
  const classifiedCatalogCount = ddosCatalogChecks.length
    + nonDdosOnlyChecks.length
    + wafOnlyChecks.length
    + mixedUnscoredChecks.length;
  if (classifiedCatalogCount !== CHECK_CATALOG.length) {
    errors.push(`catalog metadata counts do not partition all checks: ${classifiedCatalogCount}/${CHECK_CATALOG.length}`);
  }

  const payload = {
    schema: 'astranull.resource_exhaustion_taxonomy_validation.v1',
    generated_at: new Date().toISOString(),
    catalog_check_count: CHECK_CATALOG.length,
    taxonomy: {
      resource_families: EXHAUSTED_RESOURCE_FAMILIES.length,
      attack_vectors: summary.total,
      coverage: {
        implemented: summary.implemented,
        partial: summary.partial,
        soc_only: summary.soc_only,
        pending: summary.pending,
        implemented_or_partial_pct: Math.round(((summary.implemented + summary.partial + summary.soc_only) / summary.total) * 1000) / 10,
      },
      by_exhausted_resource: summary.by_resource,
    },
    tasks: RESOURCE_EXHAUSTION_TASKS.map((task) => ({
      ...task,
      attack_count: ATTACK_VECTOR_REGISTRY.filter((e) => e.task_id === task.id).length,
      pending_count: ATTACK_VECTOR_REGISTRY.filter((e) => e.task_id === task.id && e.coverage_status === 'pending').length,
    })),
    family_build_specs: FAMILY_BUILD_SPECS.map((spec) => ({
      id: spec.id,
      has_today_count: (spec.has_today ?? []).length,
      build_checks_count: (spec.build_checks ?? []).length,
      missing_vectors_count: (spec.missing_vectors ?? []).length,
      registry_attack_count: (spec.registry_attack_ids ?? []).length,
      task_ids: spec.task_ids ?? [],
    })),
    non_ddos_threats: NON_DDOS_AVAILABILITY_THREATS.length,
    waf_vulnerability_entries: WAF_VULNERABILITY_REGISTRY.length,
    catalog_metadata: {
      checks_with_ddos_family: ddosCatalogChecks.length,
      checks_non_ddos_only: nonDdosOnlyChecks.length,
      checks_waf_only: wafOnlyChecks.length,
      checks_mixed_unscored: mixedUnscoredChecks.length,
      classified_total: classifiedCatalogCount,
      by_exhausted_resource: CHECK_CATALOG.reduce((acc, c) => {
        if (c.exhausted_resource != null) acc[c.exhausted_resource] = (acc[c.exhausted_resource] ?? 0) + 1;
        return acc;
      }, {}),
    },
    orphan_catalog_checks: orphanCatalogChecks,
    pending_attack_ids: pendingEntries.map((e) => e.id),
    implemented_attack_ids: implementedEntries.map((e) => e.id),
    errors,
    warnings,
    ok: errors.length === 0,
  };

  return payload;
}

function main() {
  const { out } = parseArgs(process.argv);
  const result = validateResourceExhaustionTaxonomy();
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`, 'utf8');

  if (!result.ok) {
    console.error('resource-exhaustion-taxonomy: FAILED');
    for (const err of result.errors) console.error(`  - ${err}`);
    process.exit(1);
  }

  console.log(`resource-exhaustion-taxonomy: ok (${result.taxonomy.attack_vectors} vectors, ${result.taxonomy.coverage.pending} pending)`);
  console.log(`  wrote ${out}`);
  if (result.warnings.length) {
    for (const warn of result.warnings) console.warn(`  warn: ${warn}`);
  }
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  main();
}
