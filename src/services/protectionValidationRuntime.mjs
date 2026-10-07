// Dev-store and Postgres composition of the protection-validation workflow behind one service shape.
import { probeSourceResolverFromEnv } from '../lib/probeSourcePerspective.mjs';
import { incMetric } from '../lib/metrics.mjs';
import {
  advanceDueEntryPathComparisons,
  configureEntryPathComparisonRuntime,
  finalizeExpiredComparisonRuns,
  ENTRY_PATH_COMPARISON_SERVICE_METHODS,
  entryPathComparisonEvaluationRecord,
  linkEntryPathComparisonEvaluation,
  registerEntryPathComparisonFinalizedHook,
} from './entryPathComparisons.mjs';
import { createDevStoreFirewallEvidenceReader } from './firewallChangeAcceptance.mjs';
import { upsertProtectionFindingsFromEvaluation } from './findings.mjs';
import { createDevProtectionValidationBackend, createProtectionValidationService } from './protectionValidation.mjs';
import { createProtectionValidationFacade } from './protectionValidationFacade.mjs';

const ENTRY_PATH_TICK_MS = 30_000;

let sourceResolver = probeSourceResolverFromEnv();

const devBackend = createDevProtectionValidationBackend();

export const devProtectionValidationFacade = createProtectionValidationFacade({
  base: createProtectionValidationService({ backend: devBackend, resolveSourcePerspective: (workerId) => sourceResolver(workerId) }),
  backend: devBackend,
  evidence: createDevStoreFirewallEvidenceReader(),
  resolveSourcePerspective: (workerId) => sourceResolver(workerId),
  comparisons: ENTRY_PATH_COMPARISON_SERVICE_METHODS,
  findings: { upsertProtectionFindingsFromEvaluation },
});

registerEntryPathComparisonFinalizedHook(async (comparison) => {
  const stored = await devProtectionValidationFacade.recordEntryPathComparisonEvaluation(
    comparison,
    entryPathComparisonEvaluationRecord(comparison),
  );
  if (stored?.id) linkEntryPathComparisonEvaluation(comparison.tenant_id, comparison.id, stored.id);
});

/** Dev-store runtime: comparison starts follow the server probe mode; sources come from the approved registry. */
export function configureProtectionValidationRuntime(runtimeConfig, { env = process.env } = {}) {
  sourceResolver = probeSourceResolverFromEnv(env);
  configureEntryPathComparisonRuntime(runtimeConfig, { resolveSourcePerspective: sourceResolver });
}

/** Resumes deferred comparison items once cooldowns or rate windows pass; returns a stop function. */
export function startEntryPathComparisonTicker(runtimeConfig, { intervalMs = ENTRY_PATH_TICK_MS } = {}) {
  const timer = setInterval(() => {
    try {
      finalizeExpiredComparisonRuns();
      advanceDueEntryPathComparisons({ runtimeConfig });
    } catch {
      incMetric('entry_path_comparison_tick_failed');
    }
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
