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
  ATTACK_SURFACE_DOMAINS,
  COVERAGE_STATUS_SEMANTICS,
  EXHAUSTED_RESOURCE_FAMILIES,
  FAMILY_BUILD_SPECS,
  MONITOR_ONLY_VECTORS,
  NON_DDOS_AVAILABILITY_THREATS,
  OUT_OF_SCOPE_VECTORS,
  RESOURCE_EXHAUSTION_TASKS,
  WAF_VULNERABILITY_REGISTRY,
  buildResourceExhaustionCheckMetadata,
  collectMappedCheckIds,
  getAttackIdsByFamily,
  summarizeCoverage,
} from '../src/contracts/resourceExhaustionTaxonomy.mjs';
import { evidenceTierForCheck } from '../src/lib/readinessVerdicts.mjs';
import { evidenceTierForTaxonomyCheckIds } from '../src/lib/probeEvidenceTiers.mjs';
import { VECTOR_CATALOG } from '../src/lib/data/vectorCatalog.generated.mjs';

const DEFAULT_OUT = 'output/resource-exhaustion-taxonomy-validation.json';

// Keep this profile-kind routing contract in sync with workers/probe-worker.mjs until the worker exports it.
export const WORKER_EXECUTED_KIND_BY_DECLARED_KIND = Object.freeze(
  Object.fromEntries([
    'http_head', 'tcp_connect', 'dns_resolve', 'metadata_marker', 'udp_probe',
    'quic_reachability', 'alert_webhook_ping', 'ops_readiness', 'ownership_challenge',
    'tls_session', 'http2_settings', 'origin_leak_scan', 'host_sni_bypass',
    'port_scan_bounded', 'rate_limit_sequence', 'waf_enforcement_probe',
    'dnssec_posture', 'dns_open_recursion', 'dns_failover_posture', 'dns_axfr_leak',
    'tls_audit', 'cache_abuse_probe', 'api_surface_scan', 'cors_posture_probe',
    'bot_challenge_probe', 'graphql_posture_probe', 'websocket_upgrade_posture',
    'outside_in_waf_scan', 'grpc_reflection_probe', 'reflection_service_probe',
    'dns_wire_query', 'http_method_matrix', 'header_size_probe', 'slow_header_probe',
    'http2_frame_probe', 'http3_control_probe', 'waf_inspection_limit_probe',
    'waf_class_marker_probe', 'waf_evasion_marker_probe', 'l7_resource_posture_probe',
  ].map((kind) => [kind, kind])),
);

export function validateDeclaredProbeKinds(
  catalog,
  executedKindByDeclaredKind = WORKER_EXECUTED_KIND_BY_DECLARED_KIND,
) {
  const errors = [];
  for (const check of catalog) {
    const declaredKind = check.probe_profile?.kind;
    if (!declaredKind) continue;
    const executedKind = executedKindByDeclaredKind[declaredKind];
    if (executedKind !== declaredKind) {
      errors.push(`${check.check_id}: declared probe kind ${declaredKind} executes as ${executedKind ?? 'unsupported'}`);
    }
  }
  return errors;
}

export function readCommittedCatalogIds() {
  return VECTOR_CATALOG.map((row) => row.vector_id);
}

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

export function validateResourceExhaustionTaxonomy({
  externalCatalogIds = readCommittedCatalogIds(),
  registryEntries = [
    ...ATTACK_VECTOR_REGISTRY,
    ...WAF_VULNERABILITY_REGISTRY,
    ...NON_DDOS_AVAILABILITY_THREATS,
  ],
  outOfScopeVectors = OUT_OF_SCOPE_VECTORS,
} = {}) {
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
  for (const family of EXHAUSTED_RESOURCE_FAMILIES) {
    if (
      family.scored_for_ddos_readiness
      && !FAMILY_BUILD_SPECS.some((spec) => spec.id === family.id)
    ) {
      errors.push(`missing FAMILY_BUILD_SPECS for family ${family.id}`);
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
    'exhausted_resources',
    'attack_vector_ids',
    'delivery_patterns',
    'waf_vulnerability_ids',
    'non_ddos_threat_ids',
  ];
  const emptyMetadata = {
    exhausted_resource: null,
    exhausted_resources: [],
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
    if (check.evidence_tier !== evidenceTierForCheck(check)) {
      errors.push(`${check.check_id}: evidence_tier is not derived from probe_profile.kind`);
    }
    if (check.exhausted_resource !== null && !familyIdSet.has(check.exhausted_resource)) {
      errors.push(`${check.check_id}: exhausted_resource ${check.exhausted_resource} is not a known family id`);
    }
    for (const familyId of check.exhausted_resources) {
      if (!familyIdSet.has(familyId)) {
        errors.push(`${check.check_id}: exhausted_resources includes unknown family id ${familyId}`);
      }
    }
    if (check.exhausted_resource !== (check.exhausted_resources[0] ?? null)) {
      errors.push(`${check.check_id}: exhausted_resource must remain the first exhausted_resources compatibility alias`);
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
      check.exhausted_resources.length === 0
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
    if (threat.evidence_tier !== 'E5') errors.push(`${threat.id}: non-DDoS threat evidence_tier must be E5`);
    for (const checkId of threat.check_ids ?? []) {
      if (!catalogIds.has(checkId)) {
        errors.push(`${threat.id}: unknown check_id ${checkId}`);
      }
    }
  }

  for (const entry of ATTACK_VECTOR_REGISTRY) {
    if (
      !entry.id
      || !entry.name
      || !entry.exhausted_resource
      || !entry.coverage_status
      || !entry.evidence_tier
      || !entry.domain
      || !Array.isArray(entry.catalog_vector_ids)
      || !entry.task_id
    ) {
      errors.push(`attack entry missing required fields: ${entry.id ?? '(no id)'}`);
      continue;
    }
    if (!taskIds.has(entry.task_id) && !entry.task_id.startsWith('DET-00') && !entry.task_id.startsWith('SOC-')) {
      warnings.push(`${entry.id}: task_id ${entry.task_id} not in RESOURCE_EXHAUSTION_TASKS`);
    }
    const mappedChecks = [];
    for (const checkId of entry.check_ids ?? []) {
      if (!catalogIds.has(checkId)) {
        errors.push(`${entry.id}: unknown check_id ${checkId}`);
      } else {
        const check = getCheckById(checkId);
        if (!check) errors.push(`${entry.id}: getCheckById failed for ${checkId}`);
        else mappedChecks.push(check);
      }
    }

    if (!(entry.coverage_status in COVERAGE_STATUS_SEMANTICS)) {
      errors.push(`${entry.id}: unknown coverage_status ${entry.coverage_status}`);
      continue;
    }
    const expectedTier = evidenceTierForTaxonomyCheckIds(
      mappedChecks.map((check) => check.check_id),
    );
    if (entry.evidence_tier !== expectedTier) {
      errors.push(`${entry.id}: evidence_tier does not match best mapped check tier`);
    }
    const expectedStatus = expectedTier === 'E3'
      ? 'implemented'
      : expectedTier === 'E1' || expectedTier === 'E2'
        ? 'partial'
        : expectedTier === 'E4'
          ? 'soc_only'
          : 'pending';
    if (entry.coverage_status !== expectedStatus) {
      errors.push(`${entry.id}: coverage_status does not match evidence_tier ${entry.evidence_tier}`);
    }
  }

  for (const entry of WAF_VULNERABILITY_REGISTRY) {
    if (
      entry.domain !== 'A7'
      || !familyIds.has(entry.exhausted_resource)
      || !Array.isArray(entry.catalog_vector_ids)
      || !entry.evidence_tier
      || !entry.coverage_status
    ) {
      errors.push(`${entry.id}: incomplete derived WAF taxonomy metadata`);
    }
  }

  const domainIds = new Set(ATTACK_SURFACE_DOMAINS.map((domain) => domain.id));
  for (const entry of ATTACK_VECTOR_REGISTRY) {
    if (!domainIds.has(entry.domain)) errors.push(`${entry.id}: unknown attack-surface domain ${entry.domain}`);
  }
  errors.push(...validateDeclaredProbeKinds(CHECK_CATALOG));

  const summary = summarizeCoverage();
  const pendingEntries = ATTACK_VECTOR_REGISTRY.filter((e) => e.coverage_status === 'pending');
  const implementedEntries = ATTACK_VECTOR_REGISTRY.filter((e) => e.coverage_status === 'implemented');
  const externalCatalogIdCounts = new Map();
  for (const catalogId of externalCatalogIds) {
    externalCatalogIdCounts.set(catalogId, (externalCatalogIdCounts.get(catalogId) ?? 0) + 1);
  }
  const externalCatalogIdSet = new Set(externalCatalogIds);
  const duplicateExternalCatalogIds = [...externalCatalogIdCounts]
    .filter(([, count]) => count > 1)
    .map(([catalogId]) => catalogId)
    .sort();
  if (externalCatalogIds.length !== 721) {
    errors.push(`external catalog row count must be 721, found ${externalCatalogIds.length}`);
  }
  if (externalCatalogIdSet.size !== 721) {
    errors.push(`external catalog unique id count must be 721, found ${externalCatalogIdSet.size}`);
  }
  if (duplicateExternalCatalogIds.length > 0) {
    errors.push(`external catalog duplicate ids (${duplicateExternalCatalogIds.length}): ${duplicateExternalCatalogIds.join(', ')}`);
  }

  const claimsByCatalogId = new Map();
  let catalogClaimOccurrences = 0;
  for (const entry of registryEntries) {
    for (const catalogId of entry.catalog_vector_ids ?? []) {
      catalogClaimOccurrences += 1;
      if (!/^(NET|AMP|APP|WAF|EVA)-\d{3}$/.test(catalogId)) {
        errors.push(`${entry.id}: invalid catalog_vector_id ${catalogId}`);
      }
      const claims = claimsByCatalogId.get(catalogId) ?? [];
      claims.push(entry.id);
      claimsByCatalogId.set(catalogId, claims);
    }
  }
  const duplicateClaimIds = [];
  for (const [catalogId, claims] of claimsByCatalogId) {
    if (claims.length > 1) {
      duplicateClaimIds.push(catalogId);
      errors.push(`${catalogId}: duplicate registry claims ${claims.join(', ')}`);
    }
  }
  duplicateClaimIds.sort();
  const unknownClaimIds = [...claimsByCatalogId.keys()]
    .filter((catalogId) => !externalCatalogIdSet.has(catalogId))
    .sort();
  if (unknownClaimIds.length > 0) {
    errors.push(`registry claims unknown catalog ids (${unknownClaimIds.length}): ${unknownClaimIds.join(', ')}`);
  }

  const outOfScopeCatalogIds = outOfScopeVectors.flatMap((entry) => entry.catalog_vector_ids ?? []);
  const outOfScopeIdCounts = new Map();
  for (const catalogId of outOfScopeCatalogIds) {
    outOfScopeIdCounts.set(catalogId, (outOfScopeIdCounts.get(catalogId) ?? 0) + 1);
  }
  const outOfScopeIds = new Set(outOfScopeCatalogIds);
  const duplicateOutOfScopeIds = [...outOfScopeIdCounts]
    .filter(([, count]) => count > 1)
    .map(([catalogId]) => catalogId)
    .sort();
  if (duplicateOutOfScopeIds.length > 0) {
    errors.push(`out-of-scope duplicate catalog ids (${duplicateOutOfScopeIds.length}): ${duplicateOutOfScopeIds.join(', ')}`);
  }
  const unknownOutOfScopeIds = [...outOfScopeIds]
    .filter((catalogId) => !externalCatalogIdSet.has(catalogId))
    .sort();
  if (unknownOutOfScopeIds.length > 0) {
    errors.push(`out-of-scope unknown catalog ids (${unknownOutOfScopeIds.length}): ${unknownOutOfScopeIds.join(', ')}`);
  }
  const claimOutOfScopeOverlapIds = [...outOfScopeIds]
    .filter((catalogId) => claimsByCatalogId.has(catalogId))
    .sort();
  if (claimOutOfScopeOverlapIds.length > 0) {
    errors.push(`catalog ids both claimed and out-of-scope (${claimOutOfScopeOverlapIds.length}): ${claimOutOfScopeOverlapIds.join(', ')}`);
  }
  const allowedOutOfScopeReasons = new Set([
    'requires_l2_adjacency',
    'requires_rf_proximity',
    'requires_mobile_core_interface',
    'requires_routing_peer_session',
  ]);
  for (const entry of outOfScopeVectors) {
    if (!allowedOutOfScopeReasons.has(entry.reason) || !['A1b', 'A1c', 'A1d'].includes(entry.domain)) {
      errors.push(`invalid out-of-scope vector declaration: ${JSON.stringify(entry)}`);
    }
  }
  // Monitor-only annotation layer: passive detection over the OUT_OF_SCOPE_VECTORS.
  // Must reference exactly the out-of-scope ids, once each, with a family-correct
  // detection_mode/dependency. It is NOT a registry claimant (no duplicate claims).
  const monitorExpectedByReason = {
    requires_l2_adjacency: { detection_mode: 'agent_local_telemetry', dependency: 'on_network_agent_required' },
    requires_routing_peer_session: { detection_mode: 'integration_telemetry', dependency: 'routing_session_feed_required' },
    requires_rf_proximity: { detection_mode: 'integration_telemetry', dependency: 'wireless_sensor_required' },
    requires_mobile_core_interface: { detection_mode: 'integration_telemetry', dependency: 'mobile_core_tap_required' },
  };
  const monitorSeen = new Map();
  const monitorByDetectionMode = {};
  const monitorByDependency = {};
  for (const entry of MONITOR_ONLY_VECTORS) {
    if (entry.monitor_only !== true) errors.push(`${entry.id}: monitor-only vector must set monitor_only:true`);
    if (entry.evidence_tier !== 'E5') errors.push(`${entry.id}: monitor-only vector evidence_tier must be E5`);
    if (!['agent_local_telemetry', 'integration_telemetry'].includes(entry.detection_mode)) {
      errors.push(`${entry.id}: invalid monitor-only detection_mode ${entry.detection_mode}`);
    }
    if (!entry.signal_source || !entry.dependency || !entry.notes) {
      errors.push(`${entry.id}: monitor-only vector missing signal_source/dependency/notes`);
    }
    const expected = monitorExpectedByReason[entry.reason];
    if (!expected) {
      errors.push(`${entry.id}: unknown monitor-only reason ${entry.reason}`);
    } else {
      if (entry.detection_mode !== expected.detection_mode) {
        errors.push(`${entry.id}: detection_mode ${entry.detection_mode} does not match reason ${entry.reason}`);
      }
      if (entry.dependency !== expected.dependency) {
        errors.push(`${entry.id}: dependency ${entry.dependency} does not match reason ${entry.reason}`);
      }
    }
    monitorByDetectionMode[entry.detection_mode] = (monitorByDetectionMode[entry.detection_mode] ?? 0) + entry.catalog_vector_ids.length;
    monitorByDependency[entry.dependency] = (monitorByDependency[entry.dependency] ?? 0) + entry.catalog_vector_ids.length;
    for (const catalogId of entry.catalog_vector_ids) {
      if (!outOfScopeIds.has(catalogId)) {
        errors.push(`${entry.id}: monitor-only catalog id ${catalogId} is not an OUT_OF_SCOPE vector`);
      }
      if (monitorSeen.has(catalogId)) {
        errors.push(`${catalogId}: monitor-only vector claimed twice (${monitorSeen.get(catalogId)}, ${entry.id})`);
      }
      monitorSeen.set(catalogId, entry.id);
    }
  }
  const monitorUncovered = [...outOfScopeIds].filter((catalogId) => !monitorSeen.has(catalogId)).sort();
  if (monitorUncovered.length > 0) {
    errors.push(`out-of-scope vectors missing monitor-only coverage: ${monitorUncovered.join(', ')}`);
  }

  const catalogUnclaimedIds = [...externalCatalogIdSet].filter((catalogId) => (
    !claimsByCatalogId.has(catalogId) && !outOfScopeIds.has(catalogId)
  )).sort();
  if (catalogUnclaimedIds.length > 0) {
    errors.push(`unclaimed catalog vectors (${catalogUnclaimedIds.length}): ${catalogUnclaimedIds.join(', ')}`);
  }
  const canonicalDispositionIds = new Set(
    [...claimsByCatalogId.keys(), ...outOfScopeIds]
      .filter((catalogId) => externalCatalogIdSet.has(catalogId)),
  );
  if (canonicalDispositionIds.size !== externalCatalogIdSet.size) {
    errors.push(`catalog disposition partition must cover ${externalCatalogIdSet.size} unique ids, found ${canonicalDispositionIds.size}`);
  }

  const scoredFamilyIds = new Set(
    EXHAUSTED_RESOURCE_FAMILIES
      .filter((family) => family.scored_for_ddos_readiness)
      .map((family) => family.id),
  );
  const checkHasDdosFamily = (check) => check.exhausted_resources.some((familyId) => scoredFamilyIds.has(familyId));
  const ddosCatalogChecks = CHECK_CATALOG.filter(checkHasDdosFamily);
  const nonDdosOnlyChecks = CHECK_CATALOG.filter((check) => (
    !checkHasDdosFamily(check)
    && check.non_ddos_threat_ids.length > 0
    && check.waf_vulnerability_ids.length === 0
  ));
  const wafOnlyChecks = CHECK_CATALOG.filter((check) => (
    !checkHasDdosFamily(check)
    && check.waf_vulnerability_ids.length > 0
    && check.non_ddos_threat_ids.length === 0
  ));
  const mixedUnscoredChecks = CHECK_CATALOG.filter((check) => (
    !checkHasDdosFamily(check)
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
        implemented_or_partial_pct: Math.round(((summary.implemented + summary.partial) / summary.total) * 1000) / 10,
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
    catalog_partition: {
      external_rows: externalCatalogIds.length,
      external_unique_ids: externalCatalogIdSet.size,
      claim_occurrences: catalogClaimOccurrences,
      claimed_ids: claimsByCatalogId.size,
      out_of_scope_occurrences: outOfScopeCatalogIds.length,
      out_of_scope_ids: outOfScopeIds.size,
      disposition_ids: canonicalDispositionIds.size,
      duplicate_external_ids: duplicateExternalCatalogIds,
      duplicate_claim_ids: duplicateClaimIds,
      duplicate_out_of_scope_ids: duplicateOutOfScopeIds,
      unknown_claim_ids: unknownClaimIds,
      unknown_out_of_scope_ids: unknownOutOfScopeIds,
      claim_out_of_scope_overlap_ids: claimOutOfScopeOverlapIds,
      unclaimed_ids: catalogUnclaimedIds,
    },
    monitor_only: {
      entries: MONITOR_ONLY_VECTORS.length,
      catalog_ids_covered: monitorSeen.size,
      out_of_scope_ids: outOfScopeIds.size,
      by_detection_mode: monitorByDetectionMode,
      by_dependency: monitorByDependency,
      uncovered_ids: monitorUncovered,
    },
    catalog_unclaimed_count: catalogUnclaimedIds.length,
    catalog_unclaimed_ids: catalogUnclaimedIds,
    catalog_metadata: {
      checks_with_ddos_family: ddosCatalogChecks.length,
      checks_non_ddos_only: nonDdosOnlyChecks.length,
      checks_waf_only: wafOnlyChecks.length,
      checks_mixed_unscored: mixedUnscoredChecks.length,
      classified_total: classifiedCatalogCount,
      by_exhausted_resource: CHECK_CATALOG.reduce((acc, check) => {
        for (const familyId of check.exhausted_resources) {
          acc[familyId] = (acc[familyId] ?? 0) + 1;
        }
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
