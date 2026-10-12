import {
  EVIDENCE_TIER_LABELS,
  EVIDENCE_TIERS,
  OBSERVATION_ONLY_PROBE_KINDS,
  evidenceTierForCheck,
  evidenceTierForProbeKind,
} from './probeEvidenceTiers.mjs';

export {
  EVIDENCE_TIER_LABELS,
  EVIDENCE_TIERS,
  OBSERVATION_ONLY_PROBE_KINDS,
  evidenceTierForCheck,
  evidenceTierForProbeKind,
};

const READINESS_RELEVANT_VERDICTS = new Set([
  'protected',
  'pass',
  'passed',
  'success',
  'ok',
  'allowed_as_expected',
  'edge_protected',
  'exposed',
  'unprotected',
  'gap',
  'fail',
  'failed',
  'bypassable',
  'penetrated',
  'edge_exposed',
]);

const OBSERVATION_ONLY_PROBE_KIND_SET = new Set(OBSERVATION_ONLY_PROBE_KINDS);
let readinessChecksById = new Map();

export function registerReadinessCheckCatalog(catalog) {
  readinessChecksById = new Map((catalog ?? []).map((check) => [check.check_id, check]));
}

export function verdictSupportsReadiness(verdict) {
  return READINESS_RELEVANT_VERDICTS.has(verdict);
}

export function catalogCheckSupportsReadiness(checkId) {
  const check = readinessChecksById.get(checkId);
  const probeKind = check?.probe_profile?.kind;
  return typeof probeKind === 'string' && !['metadata_marker', 'ops_readiness'].includes(probeKind) && evidenceTierForCheck(check) !== 'E2' && !OBSERVATION_ONLY_PROBE_KIND_SET.has(probeKind) && check.observation_only !== true && check.readiness_conclusion !== false && check.probe_profile?.observation_only !== true && check.probe_profile?.readiness_conclusion !== false;
}

export function runVerdictSupportsReadiness(run, verdict) {
  return Boolean(
    verdict
    && catalogCheckSupportsReadiness(run?.check_id)
    && verdictSupportsReadiness(verdict.verdict),
  );
}
