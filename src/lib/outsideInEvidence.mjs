/**
 * EVIDENCE-01 / ADR-0008: scrub obsolete agent/placement vocabulary and agent identifiers from
 * CUSTOMER-FACING evidence presentation — finding explanations, verdict explanations, and
 * exported report verdict records.
 *
 * AstraNull is outside-in only: there are no internal agents, no placement diagnostics, and
 * verdicts come from external probe evidence (`external_only`). Historical rows seeded under the
 * pre-ADR-0008 model may still carry "agent"/"placement" wording and an `agent_id`. We must not
 * present that to customers or auditors. Internal/historical storage is untouched — this is a
 * read/export-time presentation scrub only.
 *
 * The rewrite is deliberately conservative: it re-labels the observer (agent -> external probe)
 * and strips the agent-only diagnostic framing. It never invents a new observation or changes
 * the verdict/confidence/evidence — "do not fabricate observed evidence".
 */

// Agent-identifier / placement-diagnostic keys that must never reach a customer-facing payload.
const AGENT_PLACEMENT_KEYS = new Set([
  'agent_id',
  'observation_mode',
]);

/**
 * Ordered phrase substitutions. Each maps pre-ADR-0008 agent/placement phrasing to external-probe
 * wording. Order matters: longer/more-specific phrases first so they win over generic fallbacks.
 * All matches are case-insensitive and global.
 *
 * @type {ReadonlyArray<[RegExp, string]>}
 */
const PHRASE_SUBSTITUTIONS = [
  [/\bbound online agent\b/gi, 'external probe'],
  [/\bthe agent observed traffic\b/gi, 'the external probe recorded traffic reaching the declared path'],
  [/\bagent observed traffic\b/gi, 'external probe recorded traffic reaching the declared path'],
  [/\bagent observation\b/gi, 'external probe observation'],
  [/\bagent placement\b/gi, 'edge protection'],
  [/\bplacement confidence\b/gi, 'external probe confidence'],
  [/\bthe agent\b/gi, 'the external probe'],
  [/\bagents\b/gi, 'external probes'],
  [/\bagent\b/gi, 'external probe'],
  [/\bplacement\b/gi, 'external probe coverage'],
];

/** Collapse the double "and edge protection" artifact a substitution can leave behind. */
const CLEANUP_SUBSTITUTIONS = [
  [/\s+and edge protection(?=\s+for this vector)/gi, ''],
  [/\s{2,}/g, ' '],
];

/** True when a string still contains agent/placement vocabulary (used by tests/guards). */
export function containsAgentPlacementVocabulary(value) {
  if (typeof value !== 'string') return false;
  return /\b(agent|agents|placement)\b/i.test(value);
}

/**
 * Rewrite a customer-facing explanation/reason string to external-probe wording.
 * @param {unknown} value
 * @returns {unknown} the rewritten string, or the input unchanged when not a string
 */
export function scrubAgentPlacementText(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  let out = value;
  for (const [pattern, replacement] of PHRASE_SUBSTITUTIONS) {
    out = out.replace(pattern, replacement);
  }
  for (const [pattern, replacement] of CLEANUP_SUBSTITUTIONS) {
    out = out.replace(pattern, replacement);
  }
  out = out.trim();
  // A substitution at the start of the sentence can lowercase the leading word
  // (e.g. "Bound online agent" -> "external probe"). Restore the leading capital.
  if (out.length > 0) {
    out = out[0].toUpperCase() + out.slice(1);
  }
  return out;
}

/**
 * Scrub a stored verdict's `placement_confidence` object for customer presentation: drop agent
 * identifier / observation-mode keys and rewrite any agent-worded `reason`. Returns `null`
 * unchanged. Does not mutate the input.
 *
 * @param {Record<string, unknown> | null | undefined} placement
 * @returns {Record<string, unknown> | null}
 */
export function scrubPlacementConfidenceForCustomer(placement) {
  if (placement === null || placement === undefined) return placement ?? null;
  if (typeof placement !== 'object' || Array.isArray(placement)) return placement;
  const out = {};
  for (const [key, value] of Object.entries(placement)) {
    if (AGENT_PLACEMENT_KEYS.has(key)) continue;
    // Only `reason` is free-text prose; other fields (level/status/score/ids) are enums or
    // identifiers and must not be re-cased or reworded.
    out[key] = key === 'reason' && typeof value === 'string' ? scrubAgentPlacementText(value) : value;
  }
  return out;
}

/**
 * Scrub a verdict record projected into a customer-facing report/finding payload: rewrites
 * `explanation` and scrubs nested `placement_confidence`. Returns a shallow copy; the stored
 * record is untouched.
 *
 * @template {Record<string, unknown>} T
 * @param {T} verdict
 * @returns {T}
 */
export function scrubVerdictForCustomer(verdict) {
  if (verdict === null || verdict === undefined || typeof verdict !== 'object') return verdict;
  const out = { ...verdict };
  if (typeof out.explanation === 'string') {
    out.explanation = scrubAgentPlacementText(out.explanation);
  }
  if ('placement_confidence' in out) {
    out.placement_confidence = scrubPlacementConfidenceForCustomer(out.placement_confidence);
  }
  return out;
}

/**
 * Scrub a finding record projected into a customer-facing GET/list/export payload. `notes` and
 * `remediation_template` are the only free-text prose fields that can carry pre-ADR-0008
 * agent/placement wording (findings seed `notes` from a verdict explanation). Returns a shallow
 * copy; the stored record is untouched. Enum/identifier fields (severity, status, check_id, …)
 * are API contracts and are preserved verbatim.
 *
 * @template {Record<string, unknown>} T
 * @param {T} finding
 * @returns {T}
 */
export function scrubFindingForCustomer(finding) {
  if (finding === null || finding === undefined || typeof finding !== 'object') return finding;
  const out = { ...finding };
  if (typeof out.notes === 'string') {
    out.notes = scrubAgentPlacementText(out.notes);
  }
  if (typeof out.remediation_template === 'string') {
    out.remediation_template = scrubAgentPlacementText(out.remediation_template);
  }
  return out;
}

/**
 * Scrub a run-detail record projected to the customer: rewrites the nested `verdict` via
 * {@link scrubVerdictForCustomer}. Returns a shallow copy; the stored run/verdict are untouched.
 *
 * @template {Record<string, unknown>} T
 * @param {T} run
 * @returns {T}
 */
export function scrubRunForCustomer(run) {
  if (run === null || run === undefined || typeof run !== 'object') return run;
  if (run.verdict === null || run.verdict === undefined) return run;
  return { ...run, verdict: scrubVerdictForCustomer(run.verdict) };
}
