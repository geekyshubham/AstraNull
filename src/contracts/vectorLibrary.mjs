import { CHECK_CATALOG } from './checks.mjs';
import {
  ATTACK_VECTOR_REGISTRY,
  NON_DDOS_AVAILABILITY_THREATS,
  OUT_OF_SCOPE_VECTORS,
  WAF_VULNERABILITY_REGISTRY,
} from './resourceExhaustionTaxonomy.mjs';
import { evidenceTierForCheck } from '../lib/probeEvidenceTiers.mjs';
import {
  VECTOR_CATALOG,
  VECTOR_CATALOG_TOTAL,
} from '../lib/data/vectorCatalog.generated.mjs';

export const VECTOR_LIBRARY_TOTAL = 721;

export const VECTOR_EVIDENCE_CAPABILITIES = Object.freeze([
  'unmapped',
  'declaration_only',
  'transport_only',
  'semantic_safe',
  'soc_governed',
  'monitor_only',
]);

export const VECTOR_EXECUTION_DISPOSITIONS = Object.freeze([
  'safe_validation_available',
  'soc_gated_only',
  'monitor_only',
  'not_currently_runnable',
]);

export const EVIDENCE_CAPABILITY_BY_TIER = Object.freeze({
  E0: 'unmapped',
  E1: 'declaration_only',
  E2: 'transport_only',
  E3: 'semantic_safe',
  E4: 'soc_governed',
  E5: 'monitor_only',
});

function sortStrings(values) {
  return [...new Set(values)].sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
}

function claimBoundary(catalogRow, claim) {
  return String(
    claim.entry.scope_boundary
      ?? claim.entry.note
      ?? claim.entry.notes
      ?? catalogRow.boundaries
      ?? '',
  ).trim();
}

function intendedDetectionGoal(catalogRow, evidenceTier) {
  const mode = evidenceTier === 'E5' ? 'monitoring' : 'validation';
  const target = catalogRow.targeted_resource_or_assumption || catalogRow.canonical_name;
  return `Intent only: assess ${mode} evidence relevant to ${target}. This is not an observed or detected result.`;
}

function mappedFailureMeaning(catalogRow, claim, checks, evidenceTier) {
  const boundary = claimBoundary(catalogRow, claim);
  const boundarySuffix = boundary ? ` Boundary: ${boundary}` : '';

  if (evidenceTier === 'E1') {
    return `Missing or contradictory declaration evidence is a readiness metadata gap only; it does not establish exposure to ${catalogRow.canonical_name}.${boundarySuffix}`;
  }
  if (evidenceTier === 'E2') {
    return `Transport evidence can establish reachability or response behavior only; it cannot by itself establish susceptibility to ${catalogRow.canonical_name}.${boundarySuffix}`;
  }
  if (evidenceTier === 'E4') {
    return `No customer-runnable check establishes ${catalogRow.canonical_name}. Only authorized SOC-governed evidence can support a vector outcome; supplemental declaration or transport evidence is not an exposure result.${boundarySuffix}`;
  }
  if (evidenceTier === 'E5') {
    return `No active outside-in result is produced for ${catalogRow.canonical_name}; coverage depends on passive agent or integrated monitoring evidence.${boundarySuffix}`;
  }

  const verdictLogic = sortStrings(
    checks
      .filter((check) => evidenceTierForCheck(check) === 'E3')
      .map((check) => String(check.verdict_logic ?? '').trim())
      .filter(Boolean),
  );
  if (verdictLogic.length > 0) return verdictLogic.join(' ');
  return `No semantic-safe result is currently defined for ${catalogRow.canonical_name}.${boundarySuffix}`;
}

function executionDisposition(claim, evidenceTier, safeCheckIds, socCheckIds) {
  if (claim.source === 'OUT_OF_SCOPE_VECTORS' || evidenceTier === 'E5') {
    return 'monitor_only';
  }
  if (evidenceTier === 'E4') return 'soc_gated_only';
  if (safeCheckIds.length > 0) return 'safe_validation_available';
  if (socCheckIds.length > 0) return 'soc_gated_only';
  return 'not_currently_runnable';
}

function createClaimIndex() {
  const claims = new Map();
  const add = (source, entry) => {
    for (const vectorId of entry.catalog_vector_ids ?? []) {
      if (claims.has(vectorId)) {
        throw new Error(
          `Vector catalog ID ${vectorId} is claimed by both ${claims.get(vectorId).source} and ${source}.`,
        );
      }
      claims.set(vectorId, { source, entry });
    }
  };

  for (const entry of ATTACK_VECTOR_REGISTRY) add('ATTACK_VECTOR_REGISTRY', entry);
  for (const entry of WAF_VULNERABILITY_REGISTRY) add('WAF_VULNERABILITY_REGISTRY', entry);
  for (const entry of NON_DDOS_AVAILABILITY_THREATS) {
    add('NON_DDOS_AVAILABILITY_THREATS', entry);
  }
  for (const entry of OUT_OF_SCOPE_VECTORS) add('OUT_OF_SCOPE_VECTORS', entry);
  return claims;
}

export function buildVectorLibrary() {
  if (VECTOR_CATALOG_TOTAL !== VECTOR_LIBRARY_TOTAL || VECTOR_CATALOG.length !== VECTOR_LIBRARY_TOTAL) {
    throw new Error(
      `Vector projection must contain exactly ${VECTOR_LIBRARY_TOTAL} rows; found ${VECTOR_CATALOG.length}.`,
    );
  }

  const checksById = new Map(CHECK_CATALOG.map((check) => [check.check_id, check]));
  const claims = createClaimIndex();
  const rows = VECTOR_CATALOG.map((catalogRow) => {
    const claim = claims.get(catalogRow.vector_id);
    if (!claim) throw new Error(`Vector catalog ID ${catalogRow.vector_id} has no registry disposition.`);

    const checkIds = sortStrings(claim.entry.check_ids ?? []);
    const checks = checkIds.map((checkId) => {
      const check = checksById.get(checkId);
      if (!check) throw new Error(`${catalogRow.vector_id} references unknown check ${checkId}.`);
      return check;
    });
    const safeChecks = checks.filter(
      (check) => check.safety_class === 'safe' || check.risk_class === 'safe',
    );
    const safeCheckIds = sortStrings(safeChecks.map((check) => check.check_id));
    const socCheckIds = sortStrings(checks
      .filter((check) => check.safety_class === 'soc_gated' || check.risk_class === 'soc_gated')
      .map((check) => check.check_id));
    if (safeCheckIds.length + socCheckIds.length !== checkIds.length) {
      throw new Error(`${catalogRow.vector_id} has a mapped check without a safe or SOC safety class.`);
    }

    const evidenceTier = claim.source === 'OUT_OF_SCOPE_VECTORS'
      ? 'E5'
      : String(claim.entry.evidence_tier ?? 'E0');
    const evidenceCapability = EVIDENCE_CAPABILITY_BY_TIER[evidenceTier];
    if (!evidenceCapability) {
      throw new Error(`${catalogRow.vector_id} has unsupported evidence tier ${evidenceTier}.`);
    }
    const metadataCheckIds = sortStrings(safeChecks
      .filter((check) => evidenceTierForCheck(check) === 'E1')
      .map((check) => check.check_id));
    const transportCheckIds = sortStrings(safeChecks
      .filter((check) => evidenceTierForCheck(check) === 'E2')
      .map((check) => check.check_id));
    const semanticSafeCheckIds = sortStrings(safeChecks
      .filter((check) => evidenceTierForCheck(check) === 'E3')
      .map((check) => check.check_id));
    const registryId = claim.source === 'OUT_OF_SCOPE_VECTORS'
      ? null
      : claim.entry.id ?? null;

    return Object.freeze({
      ...catalogRow,
      registry_source: claim.source,
      registry_id: registryId,
      registry_name: claim.entry.name ?? null,
      registry_domain: claim.entry.domain ?? null,
      exhausted_resource: claim.entry.exhausted_resource ?? null,
      coverage_status: claim.entry.coverage_status ?? null,
      out_of_scope_reason: claim.source === 'OUT_OF_SCOPE_VECTORS'
        ? claim.entry.reason
        : null,
      check_ids: Object.freeze(checkIds),
      safe_check_ids: Object.freeze(safeCheckIds),
      soc_check_ids: Object.freeze(socCheckIds),
      metadata_available: metadataCheckIds.length > 0,
      metadata_check_ids: Object.freeze(metadataCheckIds),
      transport_check_ids: Object.freeze(transportCheckIds),
      semantic_safe_check_ids: Object.freeze(semanticSafeCheckIds),
      evidence_tier: evidenceTier,
      evidence_capability: evidenceCapability,
      execution_disposition: executionDisposition(
        claim,
        evidenceTier,
        safeCheckIds,
        socCheckIds,
      ),
      intended_detection_goal: intendedDetectionGoal(catalogRow, evidenceTier),
      failure_means: mappedFailureMeaning(catalogRow, claim, checks, evidenceTier),
      expected_controls: catalogRow.primary_controls,
    });
  });

  if (claims.size !== VECTOR_LIBRARY_TOTAL) {
    const catalogIds = new Set(VECTOR_CATALOG.map((row) => row.vector_id));
    const unknownClaims = [...claims.keys()].filter((vectorId) => !catalogIds.has(vectorId));
    throw new Error(
      `Registry disposition count must be ${VECTOR_LIBRARY_TOTAL}; found ${claims.size}`
      + (unknownClaims.length ? ` (unknown: ${unknownClaims.join(', ')})` : ''),
    );
  }
  if (new Set(rows.map((row) => row.vector_id)).size !== VECTOR_LIBRARY_TOTAL) {
    throw new Error('Vector library contains duplicate Vector IDs.');
  }
  return Object.freeze(rows);
}

export const VECTOR_LIBRARY = buildVectorLibrary();
const VECTOR_LIBRARY_BY_ID = new Map(VECTOR_LIBRARY.map((row) => [row.vector_id, row]));

export function getVectorById(vectorId) {
  return VECTOR_LIBRARY_BY_ID.get(vectorId) ?? null;
}
