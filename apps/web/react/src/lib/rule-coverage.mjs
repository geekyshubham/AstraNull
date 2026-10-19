import { checkPresentation } from './check-presentation.mjs';
/** Rule coverage view model: assurance is the best AstraNull can conclude; status is this target's fresh evidence. */
import { requiredDeclarationCopy, requiredDeclarationSentence } from './control-declarations.mjs';

export const ASSURANCE_META = Object.freeze({
  verdict: Object.freeze({ label: 'Verdict', rank: 9, description: 'Outside-in checks can show this rule family passing or failing.' }),
  violation_only: Object.freeze({ label: 'Exposure-only', rank: 8, description: 'Can report a violation of what you declared. A clean result is never shown as protected, because silence from outside does not prove a firewall rule.' }),
  partial: Object.freeze({ label: 'Partial', rank: 7, description: 'Only part of the rule family is tested, for example only AstraNull\'s own token rather than real attack patterns.' }),
  observation: Object.freeze({ label: 'Observes only', rank: 6, description: 'Records behaviour for context but never concludes pass or fail.' }),
  declaration: Object.freeze({ label: 'Declaration only', rank: 5, description: 'Relies on your written statement. No traffic is sent.' }),
  soc_only: Object.freeze({ label: 'SOC only', rank: 4, description: 'Run only by AstraNull SOC under an approved authorization, never self-serve.' }),
  missing: Object.freeze({ label: 'Missing', rank: 3, description: 'No check covers this rule family yet.' }),
  not_assessable: Object.freeze({ label: 'Not assessable', rank: 2, description: 'Cannot be concluded from outside your network with the probes AstraNull runs.' }),
  out_of_scope: Object.freeze({ label: 'Out of scope', rank: 1, description: 'Needs a vantage point inside your network, which the outside-in model rules out.' }),
});

export const COVERAGE_STATUS_META = Object.freeze({
  covered_fail: Object.freeze({ label: 'Fail', tone: 'danger', rank: 0, description: 'A fresh result shows this rule family not enforced.' }),
  inconclusive: Object.freeze({ label: 'Inconclusive', tone: 'warn', rank: 1, description: 'A fresh result exists but could not be attributed to the control.' }),
  needs_declaration: Object.freeze({ label: 'Needs declaration', tone: 'warn', rank: 2, description: 'Declare the missing control before this can be checked.' }),
  covered_pass: Object.freeze({ label: 'Pass', tone: 'success', rank: 3, description: 'Every fresh result for this rule family passed.' }),
  not_run: Object.freeze({ label: 'Not run', tone: 'muted', rank: 4, description: 'No result inside the freshness window.' }),
  not_assessable: Object.freeze({ label: 'Not assessable', tone: 'muted', rank: 5, description: 'Cannot be concluded from outside-in evidence.' }),
  out_of_scope: Object.freeze({ label: 'Out of scope', tone: 'muted', rank: 6, description: 'Outside what an outside-in platform can observe.' }),
});

export const LAYER_META = Object.freeze({
  waf: Object.freeze({ label: 'Web application firewall', short: 'WAF', description: 'Rules that inspect HTTP requests and responses.' }),
  nfw: Object.freeze({ label: 'Network firewall', short: 'NFW', description: 'Rules that allow or deny connections by protocol, port and source.' }),
});

/** Server copy is plain language; only the `not_runnable_reason` code still needs words. */
export const NOT_RUNNABLE_REASON_COPY = Object.freeze({
  two_perspectives_required: 'Needs at least two registered probe source locations; only one is available.',
});

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

/** Display names follow the portal vocabulary, which avoids bare "API". */
export function plainCoverageName(value) {
  const plain = text(value).replace(/\bAPI[- ]?Gateway\b/g, 'application gateway').replace(/\bAPIs\b/g, 'web services').replace(/\bAPI\b/g, 'web service');
  return plain ? `${plain.charAt(0).toUpperCase()}${plain.slice(1)}` : plain;
}

function sentence(value) {
  const raw = text(value);
  return raw ? `${raw.charAt(0).toUpperCase()}${raw.slice(1)}` : raw;
}

export function assuranceMeta(id) {
  return ASSURANCE_META[text(id)] ?? ASSURANCE_META.missing;
}

export function coverageStatusMeta(id) {
  return COVERAGE_STATUS_META[text(id)] ?? COVERAGE_STATUS_META.not_run;
}

function checkRow(raw) {
  const check = record(raw) ?? {};
  const status = text(check.status);
  return {
    checkId: text(check.check_id),
    name: checkPresentation(check.check_id).name,
    present: check.present !== false,
    assurance: text(check.assurance) || 'missing',
    status,
    statusLabel: status ? coverageStatusMeta(status === 'not_run' && check.stale === true ? 'not_run' : status).label : '',
    stale: check.stale === true,
    observedAt: text(check.observed_at),
    verdict: text(check.verdict),
  };
}

/** Normalized categories from either the catalog or the per-target payload. */
export function normalizeRuleCoverage(payload) {
  const body = record(payload);
  const categories = list(body?.categories).map((raw) => {
    const category = record(raw) ?? {};
    const assurance = text(category.assurance) || 'missing';
    const status = text(category.status);
    const missing = list(category.missing_declarations).map(text).filter(Boolean);
    const required = list(category.required_declarations).map(text).filter(Boolean);
    const reasonCode = text(category.not_runnable_reason);
    const reason = text(category.out_of_scope_reason) || text(category.not_assessable_reason) || NOT_RUNNABLE_REASON_COPY[reasonCode] || '';
    const assuranceReason = assurance === 'partial' || assurance === 'observation' ? text(category.assurance_reason) : '';
    return {
      id: text(category.id),
      layer: text(category.layer) === 'nfw' ? 'nfw' : 'waf',
      name: plainCoverageName(text(category.name) || text(category.id)),
      description: text(category.description),
      assurance,
      assuranceLabel: assuranceMeta(assurance).label,
      assuranceReason: sentence(assuranceReason),
      status,
      statusLabel: status ? coverageStatusMeta(status).label : '',
      statusTone: status ? coverageStatusMeta(status).tone : 'muted',
      reason,
      requiredDeclarations: required,
      requiredSentence: requiredDeclarationSentence(required),
      missingDeclarations: missing,
      ctas: missing.filter((key) => requiredDeclarationCopy(key).section).map((key) => ({ key, ...requiredDeclarationCopy(key) })),
      missingWithoutCta: requiredDeclarationSentence(missing.filter((key) => !requiredDeclarationCopy(key).section)),
      checks: list(category.checks).map(checkRow).filter((check) => check.checkId),
    };
  }).filter((category) => category.id);
  const freshness = record(body?.freshness_policy);
  const maxAgeMs = Number(freshness?.max_age_ms);
  return {
    version: text(body?.version),
    targetId: text(body?.target_id),
    freshnessDays: Number.isFinite(maxAgeMs) && maxAgeMs > 0 ? Math.round(maxAgeMs / 86_400_000) : null,
    categories,
  };
}

export function filterCoverageByLayer(categories, layer) {
  return layer === 'waf' || layer === 'nfw' ? list(categories).filter((category) => category.layer === layer) : list(categories);
}

/** Status counts for the summary strip; every category lands in exactly one bucket. */
export function coverageStatusCounts(categories) {
  const counts = Object.fromEntries(Object.keys(COVERAGE_STATUS_META).map((key) => [key, 0]));
  for (const category of list(categories)) {
    if (category.status && Object.hasOwn(counts, category.status)) counts[category.status] += 1;
  }
  return counts;
}

export function assuranceCounts(categories) {
  const counts = Object.fromEntries(Object.keys(ASSURANCE_META).map((key) => [key, 0]));
  for (const category of list(categories)) {
    if (Object.hasOwn(counts, category.assurance)) counts[category.assurance] += 1;
  }
  return counts;
}

/** Target view: failures and gaps first, then the rest in catalog order. */
export function sortCoverageForAttention(categories) {
  return list(categories)
    .map((category, index) => ({ category, index }))
    .sort((left, right) => (coverageStatusMeta(left.category.status).rank - coverageStatusMeta(right.category.status).rank) || left.index - right.index)
    .map(({ category }) => category);
}
