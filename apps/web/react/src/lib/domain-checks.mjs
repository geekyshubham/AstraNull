/**
 * Pure logic for the target ("domain") page: the run-all check set, per-check status rows,
 * WAF/CDN edge-evidence signals, and WAF/CDN efficacy derived from check verdicts.
 *
 * Evidence over assertion: a check only counts toward efficacy when it produced a definitive
 * external-probe verdict. Transport-only (E2) checks are shown as observations and never score;
 * declaration-only (E1) checks perform no network I/O and are not part of "run all".
 */
import { checkExclusionReason, checkSupportsTarget } from './check-picker.mjs';
import { checkPrerequisite, needsTargetAnswer } from './control-declarations.mjs';
import { MAX_SCAN_CHECKS } from './validation-scan.mjs';
import { requiredInputMissing } from './missing-input.mjs';
import { plainCheckName, plainVerdictShortLabel } from './plain-language.mjs';
import { OBSERVATION_ONLY_PROBE_KINDS } from '../../../../../src/lib/probeEvidenceTiers.mjs';

export const EDGE_DETECTION_CHECK_ID = 'waf.fingerprint.safe';
export const ORIGIN_LOCKDOWN_CHECK_ID = 'nfw.origin_lockdown.safe';
const ORIGIN_LOCKDOWN_CHECK_IDS = new Set([ORIGIN_LOCKDOWN_CHECK_ID, 'origin.direct_reachability.safe']);
const DECLARATION_ONLY_KIND = 'metadata_marker';
const VIOLATION_FAMILIES = new Set(['l3_l4', 'reflection', 'amplification']);

/** Vector family → category. `layer` decides which efficacy (WAF or CDN) a verdict feeds. */
export const CHECK_CATEGORIES = Object.freeze({
  waf: { id: 'waf', label: 'Web application firewall', layer: 'waf', icon: 'shield', how: 'Sends bounded safe markers and records external responses against the check expectation. It does not establish internal application receipt or attribute a response to a specific protection layer.' },
  exploit: { id: 'exploit', label: 'Exploit classes', layer: 'waf', icon: 'bug', how: 'Records declared readiness for known exploit classes. No live traffic is sent.' },
  origin: { id: 'origin', label: 'Origin exposure', layer: 'origin', icon: 'server', how: 'Samples a declared alternate endpoint with approved Host/SNI. A response alone does not identify your application, confirm bypass, or prove origin lockdown.' },
  l7: { id: 'l7', label: 'HTTP application layer', layer: 'cdn', icon: 'globe', how: 'Bounded HTTP probes for rate limiting, slow requests, cache abuse, and bot challenges at the edge.' },
  protocol: { id: 'protocol', label: 'Protocol machinery', layer: 'cdn', icon: 'workflow', how: 'HTTP/2, HTTP/3 (QUIC), WebSocket, and gRPC handshake posture probes.' },
  tls: { id: 'tls', label: 'TLS', layer: 'cdn', icon: 'lock', how: 'TLS version, cipher, session, and renegotiation posture checks.' },
  l3_l4: { id: 'l3_l4', label: 'Network and transport', layer: 'cdn', icon: 'network', how: 'TCP and UDP reachability and firewall exposure checks against the declared target.' },
  dns: { id: 'dns', label: 'DNS', layer: 'cdn', icon: 'dns', how: 'Direct DNS queries for resolver, recursion, DNSSEC, zone transfer, and failover posture.' },
  reflection: { id: 'reflection', label: 'Reflection exposure', layer: 'cdn', icon: 'radio', how: 'Records the response, if any, to a bounded approved protocol sample. Silence does not establish that the service is closed or protected.' },
  amplification: { id: 'amplification', label: 'Amplification exposure', layer: 'cdn', icon: 'waves', how: 'Records request and response sizes only when captured for the bounded sample. It does not establish amplification or flood capacity beyond that sample.' },
  pattern: { id: 'pattern', label: 'Delivery patterns', layer: 'cdn', icon: 'activity', how: 'Records declared readiness for multi-vector and pulse delivery patterns. No live traffic is sent.' },
  operations: { id: 'operations', label: 'Operational readiness', layer: 'ops', icon: 'bell', how: 'Alerting, runbook, and kill-switch readiness self-checks. No traffic reaches your target.' },
  path: { id: 'path', label: 'Protected path', layer: 'cdn', icon: 'globe', how: 'Records a bounded external canary response on the declared path. Without internal receipt evidence it does not confirm arrival or protection inside the application.' },
  high_scale: { id: 'high_scale', label: 'High-scale readiness', layer: 'cdn', icon: 'activity', how: 'SOC-governed high-scale scenarios. These are arranged with AstraNull SOC; customers cannot start or schedule them.' },
});
const OTHER_CATEGORY = Object.freeze({ id: 'other', label: 'Other', layer: 'other', icon: 'shield', how: 'Bounded external check.' });
const CATEGORY_ORDER = ['waf', 'origin', 'l7', 'path', 'protocol', 'tls', 'l3_l4', 'dns', 'reflection', 'amplification', 'operations', 'exploit', 'pattern', 'high_scale'];

const PASS_VERDICTS = new Set(['protected', 'pass', 'passed', 'success', 'ok', 'edge_protected', 'allowed_as_expected']);
const FAIL_VERDICTS = new Set(['edge_exposed', 'exposed', 'unprotected', 'gap', 'fail', 'failed', 'bypassable', 'penetrated']);
const ACTIVE_RUN_STATUSES = new Set(['pending', 'planned', 'queued', 'running', 'collecting']);
const STEP_STATUS = Object.freeze({ pending: 'queued', deferred: 'waiting', starting: 'running', running: 'running', collecting: 'running', denied: 'blocked', skipped: 'skipped', cancelled: 'cancelled' });

export const ROW_STATUS_META = Object.freeze({
  passed: { label: plainVerdictShortLabel('protected'), tone: 'success' },
  failed: { label: plainVerdictShortLabel('gap'), tone: 'danger' },
  inconclusive: { label: 'Inconclusive', tone: 'warn' },
  not_tested: { label: 'Not tested', tone: 'muted' },
  observed: { label: 'Observed', tone: 'muted' },
  running: { label: 'Running', tone: 'info' },
  queued: { label: 'Queued', tone: 'muted' },
  waiting: { label: 'Waiting', tone: 'warn' },
  blocked: { label: 'Not run · safety gate', tone: 'warn' },
  skipped: { label: 'Skipped', tone: 'muted' },
  cancelled: { label: 'Cancelled', tone: 'muted' },
  not_run: { label: 'Not run yet', tone: 'muted' },
});
export const ROW_STATUS_ORDER = ['failed', 'running', 'waiting', 'queued', 'inconclusive', 'not_tested', 'blocked', 'passed', 'observed', 'skipped', 'cancelled', 'not_run'];

function text(value) {
  return String(value ?? '').trim();
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

/** Current inconclusive observations are evaluated live attempts, not invalid retained proof. */
export function retainedCoveragePairs(pairs) {
  return list(pairs).filter((pair) => pair?.live_external === false
    && ['partial', 'unknown', 'stale'].includes(text(pair.state))
    && text(record(pair.retained)?.verdict));
}

function titleCase(value) {
  return text(value).replace(/[_-]+/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

export function categoryForCheck(check) {
  return CHECK_CATEGORIES[text(check?.vector_family)] ?? OTHER_CATEGORY;
}

function tierOf(check) {
  return text(check?.evidence_tier).toUpperCase();
}

/** Only graded E3 checks that are not observation-only can produce a readiness verdict. */
function isReadinessCapable(check) {
  return check?.observation_only !== true
    && check?.probe_profile?.observation_only !== true
    && check?.probe_profile?.readiness_conclusion !== false
    && tierOf(check) === 'E3';
}

/** E1 checks perform no network I/O and always verdict inconclusive, so they are not "run". */
export function isDeclarationOnlyCheck(check) {
  return tierOf(check) === 'E1' || text(check?.probe_profile?.kind) === DECLARATION_ONLY_KIND;
}

function runOrder(check) {
  if (text(check.check_id) === EDGE_DETECTION_CHECK_ID) return 0;
  if (text(check.vector_family) === 'origin') return 1;
  return tierOf(check) === 'E3' ? 2 : 3;
}

function serverRunnableAnswer(check, context) {
  const index = context?.serverRunnableIndex;
  if (!(index instanceof Map)) return null;
  const value = index.get(text(check?.check_id));
  if (typeof value === 'boolean') return value;
  return typeof record(value)?.runnable === 'boolean' ? value.runnable : null;
}

// When the server supplies every input itself (ADR-0016 amendment), its per-target answer decides; it never guesses inputs here.
function serverSuppliedRunnable(check, context) {
  return context?.serverSuppliesInput === true && serverRunnableAnswer(check, context) === true;
}

// Older/full catalog projections may omit the server's input flag. Known setup-input
// protocols still cannot enter an automatic assessment or infer authorization from metadata.
function requiresDedicatedCheckInput(check, context = null) {
  if (serverSuppliedRunnable(check, context)) return false;
  if (text(check?.check_id) === ORIGIN_LOCKDOWN_CHECK_ID) return check?.requires_additional_input === true;
  // Target-dependent requirements are answered per target by the server; without that answer the check waits.
  if (needsTargetAnswer(check)) return check?.requires_additional_input !== false;
  return check?.requires_additional_input === true
    || ['host_sni_bypass', 'alert_webhook_ping'].includes(check?.probe_profile?.kind)
    || list(check?.required_customer_setup).some((value) => typeof value === 'string'
      && value.startsWith('declared_') && value.endsWith('_probe_path'));
}

/** Adds checks the server lists as runnable on this target only; when the server supplies inputs, every check it lists as runnable. */
export function withTargetRunnableChecks(checks, targetCatalog, { serverSuppliesInput = false } = {}) {
  const base = list(checks);
  const known = new Set(base.map((check) => text(check?.check_id)));
  const extra = list(targetCatalog).filter((check) => check?.requires_additional_input === false
    && (needsTargetAnswer(check) || (serverSuppliesInput === true && !text(check?.additional_input_reason)))
    && !known.has(text(check?.check_id)));
  return extra.length ? [...base, ...extra] : base;
}

/** Customer-runnable network checks, including observations, available individually. */
export function individualChecks(checks, target, context = null) {
  const eligible = list(checks).filter((check) => text(check?.check_id)
    && !checkExclusionReason(check)
    && checkSupportsTarget(check, target)
    && !requiresDedicatedCheckInput(check, context)
    && check.probe_profile?.kind !== 'ops_readiness'
    && !isDeclarationOnlyCheck(check));
  return [...new Map(eligible.map((check) => [text(check.check_id), check])).values()];
}

function prerequisitesMet(check, target, context) {
  return !context || checkPrerequisite(check, { ...context, target }).state === 'ready';
}

/** Complete bounded network assessment; with a prerequisite context, checks awaiting a port or declaration are left out. */
export function assessmentChecks(checks, target, context = null) {
  return individualChecks(checks, target, context)
    .filter((check) => prerequisitesMet(check, target, context))
    .map((check, index) => ({ check, index }))
    .sort((left, right) => runOrder(left.check) - runOrder(right.check) || left.index - right.index)
    .slice(0, MAX_SCAN_CHECKS)
    .map(({ check }) => check);
}

/** Explanation for catalog entries outside this target's automatic network assessment. */
export function targetCheckRequirement(check, target, context = null) {
  const prerequisite = checkPrerequisite(check, { ...(context ?? {}), target });
  if (prerequisite.reason || ['needs_port', 'needs_deny_or_port', 'needs_perspectives', 'checking'].includes(prerequisite.state)) return prerequisite.detail;
  const restriction = checkExclusionReason(check);
  if (restriction === 'soc_gated') return 'Requires SOC approval and a governed execution workflow.';
  if (restriction) return 'Requires a dedicated workflow; direct customer execution is unavailable.';
  if (!checkSupportsTarget(check, target)) return `Declare a compatible endpoint (${list(check.supported_targets).join(', ')}).`;
  if (check.probe_profile?.kind === 'alert_webhook_ping' && !serverSuppliedRunnable(check, context)) return 'Requires approved signed alert-webhook scope and its dedicated workflow; no callback is inferred from catalog metadata.';
  if (requiresDedicatedCheckInput(check, context)) return 'Declare the origin binding or application probe path before using its dedicated workflow.';
  if (isDeclarationOnlyCheck(check) || check.probe_profile?.kind === 'ops_readiness') return 'Declaration or operational evidence only; sends no external traffic.';
  return '';
}

/** Readiness checks ordered with origin exposure first, capped at the scan contract limit. */
export function runAllChecks(checks, target, context = null) {
  return individualChecks(checks, target, context)
    .filter((check) => prerequisitesMet(check, target, context))
    .filter((check) => tierOf(check) !== 'E2'
      && !OBSERVATION_ONLY_PROBE_KINDS.includes(check.probe_profile?.kind))
    .map((check, index) => ({ check, index }))
    .sort((left, right) => runOrder(left.check) - runOrder(right.check) || left.index - right.index)
    .slice(0, MAX_SCAN_CHECKS)
    .map(({ check }) => check);
}

/** Declaration-only checks that apply to the target: listed, never dispatched. */
export function declarationOnlyChecks(checks, target) {
  return list(checks).filter((check) => text(check?.check_id)
    && !checkExclusionReason(check)
    && checkSupportsTarget(check, target)
    && isDeclarationOnlyCheck(check));
}

function verdictValue(value) {
  if (typeof value === 'string') return text(value);
  return text(record(value)?.verdict ?? record(value)?.result);
}

function verdictEvidenceIds(run) {
  const own = list(run?.evidence_ids);
  const nested = list(record(run?.verdict)?.evidence_ids);
  return [...own, ...nested].map(text).filter(Boolean);
}

/** Network-firewall and origin checks that can report a declared-rule violation but never a pass. */
export function isViolationOnlyCheck(check) {
  const id = text(check?.check_id);
  const family = text(check?.vector_family);
  return id.startsWith('nfw.') || VIOLATION_FAMILIES.has(family) || ORIGIN_LOCKDOWN_CHECK_IDS.has(id);
}

function classifyVerdict(verdict, check) {
  // Retained legacy grades cannot turn a currently observational check into protection credit,
  // but a violation-only check may still report the exposure it was built to find.
  if (tierOf(check) === 'E2' || OBSERVATION_ONLY_PROBE_KINDS.includes(check?.probe_profile?.kind)) {
    return isViolationOnlyCheck(check) && FAIL_VERDICTS.has(verdict.toLowerCase()) ? 'failed' : 'observed';
  }
  if (isDeclarationOnlyCheck(check)) return 'inconclusive';
  const key = verdict.toLowerCase();
  if (PASS_VERDICTS.has(key)) return 'passed';
  if (FAIL_VERDICTS.has(key)) return 'failed';
  return tierOf(check) === 'E2' ? 'observed' : 'inconclusive';
}

function runTime(run) {
  return text(run?.started_at ?? run?.created_at);
}

/** Newest run per check id from an unordered run list. */
export function latestRunByCheck(runs) {
  const latest = new Map();
  for (const run of list(runs)) {
    const checkId = text(run?.check_id);
    if (!checkId) continue;
    const previous = latest.get(checkId);
    if (!previous || runTime(run).localeCompare(runTime(previous)) > 0) latest.set(checkId, run);
  }
  return latest;
}

function rowFromStep(step, check) {
  const status = text(step.status);
  const verdict = record(step.verdict);
  const verdictText = verdictValue(verdict);
  const missingInput = status === 'verdicted' ? requiredInputMissing(step) : null;
  let rowStatus = STEP_STATUS[status] ?? 'queued';
  if (status === 'verdicted') rowStatus = missingInput ? 'not_tested' : verdictText ? classifyVerdict(verdictText, check) : 'inconclusive';
  return {
    status: rowStatus,
    verdict: verdictText,
    explanation: missingInput ? missingInput.message : text(verdict?.explanation),
    missingInput,
    expectedBehavior: text(step.expected_behavior ?? check.default_expected_behavior),
    reason: text(step.error_code) || text(step.skip_reason),
    eligibleAt: text(step.eligible_at),
    runId: text(step.test_run_id),
    startedAt: text(step.started_at),
    finishedAt: text(step.completed_at),
    request: record(step.request),
    response: record(step.response),
    requestsSent: step.requests_sent ?? null,
    requestsSimulated: step.requests_simulated === true,
    source: 'scan',
  };
}

function rowFromRun(run, check) {
  const runStatus = text(run.status).toLowerCase();
  const verdictText = verdictValue(run.verdict);
  const published = verdictText && !['unknown', 'pending', 'none'].includes(verdictText.toLowerCase());
  const missingInput = ACTIVE_RUN_STATUSES.has(runStatus) || runStatus === 'cancelled' ? null : requiredInputMissing(run);
  let rowStatus;
  if (ACTIVE_RUN_STATUSES.has(runStatus)) rowStatus = 'running';
  else if (runStatus === 'cancelled') rowStatus = 'cancelled';
  else if (missingInput) rowStatus = 'not_tested';
  // A verdict without cited evidence is not a result (same rule as the run tables).
  else if (published && verdictEvidenceIds(run).length > 0) rowStatus = classifyVerdict(verdictText, check);
  else rowStatus = tierOf(check) === 'E2' ? 'observed' : 'inconclusive';
  return {
    status: rowStatus,
    verdict: published ? verdictText : '',
    explanation: missingInput ? missingInput.message : text(record(run.verdict)?.explanation),
    missingInput,
    expectedBehavior: text(run.expected_behavior ?? check.default_expected_behavior),
    reason: '',
    eligibleAt: '',
    runId: text(run.id),
    startedAt: runTime(run),
    finishedAt: text(run.completed_at ?? run.verdict_at),
    request: null,
    response: record(run.response ?? run.last_result),
    requestsSent: null,
    requestsSimulated: false,
    source: 'run',
  };
}

function emptyRow() {
  return {
    status: 'not_run', verdict: '', explanation: '', missingInput: null, expectedBehavior: '', reason: '', eligibleAt: '', runId: '', startedAt: '', finishedAt: '',
    request: null, response: null, requestsSent: null, requestsSimulated: false, source: 'none',
  };
}

/**
 * One row per run-all check. The latest scan's step wins unless a newer standalone run of the
 * same check exists (for example the automatic edge detection after a scan finished).
 */
export function buildCheckRows({ checks, scan = null, runs = [] }) {
  const stepByCheck = new Map(list(scan?.steps).map((step) => [text(step.check_id), step]));
  const latestRuns = latestRunByCheck(runs);
  const scanStartedAt = text(scan?.created_at ?? scan?.started_at);
  return list(checks).map((check) => {
    const checkId = text(check.check_id);
    const step = stepByCheck.get(checkId) ?? null;
    const run = latestRuns.get(checkId) ?? null;
    const runIsNewer = run && text(step?.test_run_id) !== text(run.id) && (!scanStartedAt || runTime(run).localeCompare(scanStartedAt) > 0);
    const base = step && !runIsNewer ? rowFromStep(step, check) : run ? rowFromRun(run, check) : emptyRow();
    const meta = ROW_STATUS_META[base.status] ?? ROW_STATUS_META.not_run;
    return {
      ...base,
      checkId,
      name: plainCheckName(text(check.name) || checkId),
      description: text(check.description),
      verdictLogic: text(check.verdict_logic),
      expectedBehavior: text(check.default_expected_behavior ?? base.expectedBehavior),
      tier: tierOf(check),
      readinessCapable: isReadinessCapable(check),
      probeKind: text(check.probe_profile?.kind),
      markerClass: text(check.probe_profile?.marker_class),
      assuranceScope: text(check.probe_profile?.assurance_scope),
      maxRequests: Number.isFinite(Number(check.probe_profile?.max_requests)) ? Number(check.probe_profile.max_requests) : null,
      timeoutMs: Number.isFinite(Number(check.probe_profile?.timeout_ms)) ? Number(check.probe_profile.timeout_ms) : null,
      category: categoryForCheck(check),
      label: meta.label,
      tone: meta.tone,
    };
  });
}

const RECORDED_RESULT_STATUSES = new Set(['passed', 'failed', 'inconclusive']);
const STARTER_PROBE_KIND = 'waf_class_marker_probe';

/**
 * First verdict-capable check to suggest before anything has a recorded result. Rate-limit
 * canaries and observation checks are never suggested as the starter.
 */
export function recommendedStarterRow(rows) {
  const all = list(rows);
  if (all.some((row) => RECORDED_RESULT_STATUSES.has(row?.status))) return null;
  const candidates = all.filter((row) => row?.readinessCapable === true
    && row.status === 'not_run'
    && !/rate_limit/.test(text(row.probeKind)));
  return candidates.find((row) => row.probeKind === STARTER_PROBE_KIND) ?? candidates[0] ?? null;
}

export function countRowStatuses(rows) {
  const counts = Object.fromEntries(Object.keys(ROW_STATUS_META).map((key) => [key, 0]));
  for (const row of list(rows)) counts[row.status] = (counts[row.status] ?? 0) + 1;
  return counts;
}

/** Rows grouped by category in display order, each with its own status counts. */
export function groupRowsByCategory(rows) {
  const groups = new Map();
  for (const row of list(rows)) {
    const id = row.category?.id ?? 'other';
    if (!groups.has(id)) groups.set(id, { category: row.category ?? OTHER_CATEGORY, rows: [] });
    groups.get(id).rows.push(row);
  }
  const rank = (id) => {
    const index = CATEGORY_ORDER.indexOf(id);
    return index === -1 ? CATEGORY_ORDER.length : index;
  };
  return [...groups.values()]
    .sort((left, right) => rank(left.category.id) - rank(right.category.id))
    .map((group) => ({
      ...group,
      rows: [...group.rows].sort((left, right) => ROW_STATUS_ORDER.indexOf(left.status) - ROW_STATUS_ORDER.indexOf(right.status)),
      counts: countRowStatuses(group.rows),
    }));
}

/** Completed share of a run-all plan, for the progress bar. */
export function rowProgress(rows) {
  const total = list(rows).length;
  if (!total) return { total: 0, done: 0, percent: 0 };
  const done = list(rows).filter((row) => !['running', 'queued', 'waiting', 'not_run'].includes(row.status)).length;
  return { total, done, percent: Math.round((done / total) * 100) };
}

const DEFAULT_FRESHNESS_MS = 7 * 24 * 60 * 60 * 1000;
/** A layer is "Protecting" only with at least this much fresh, concluded evidence. */
export const EFFICACY_MINIMUM = Object.freeze({ concluded: 3, ruleCategories: 2 });
const CDN_EFFICACY_CATEGORIES = new Set(['l7', 'protocol', 'tls', 'path']);
const MANAGED_SCOPE = 'managed_rule_marker';

function freshnessWindowMs(coverage) {
  const value = Number(record(record(coverage)?.freshness_policy)?.max_age_ms);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_FRESHNESS_MS;
}

const PAIR_INDEX_CACHE = new WeakMap();

function pairIndex(coverage) {
  const source = record(coverage);
  if (source && PAIR_INDEX_CACHE.has(source)) return PAIR_INDEX_CACHE.get(source);
  const direct = new Map();
  const members = new Map();
  for (const pair of list(record(coverage)?.pairs)) {
    if (record(pair) && pair.custom_canary_rollup !== true) direct.set(text(pair.check_id), pair);
  }
  // A custom-canary rollup row keeps the worst member's state; its members carry the server's own freshness answer.
  const rollups = [...list(record(coverage)?.custom_canary_rollups), ...list(record(coverage)?.pairs).filter((pair) => record(pair)?.custom_canary_rollup === true)];
  for (const rollup of rollups) {
    for (const member of list(record(rollup)?.rolled_up_pairs)) {
      const id = text(record(member)?.check_id);
      if (!id) continue;
      const known = members.get(id) ?? [];
      if (!known.some((entry) => text(entry.last_run_id) === text(member.last_run_id))) known.push(member);
      members.set(id, known);
    }
  }
  const index = { direct, members };
  if (source) PAIR_INDEX_CACHE.set(source, index);
  return index;
}

/** Whether a recorded pass/fail still counts: server pair or rolled-up member state, else the row's age. */
export function rowEvidenceState(row, { coverage = null, nowMs = Date.now() } = {}) {
  if (!['passed', 'failed'].includes(row?.status)) return 'none';
  const index = pairIndex(coverage);
  const pair = index.direct.get(text(row.checkId));
  if (pair && (!text(pair.last_run_id) || text(pair.last_run_id) === text(row.runId))) {
    const state = text(pair.state);
    if (state === 'conclusive') return 'fresh';
    if (state === 'stale') return 'stale';
    if (state === 'partial' || state === 'unknown') return 'version_gap';
  }
  // A member speaks for the run the server graded; another run of the same check falls back to its own age.
  const candidates = index.members.get(text(row.checkId)) ?? [];
  const member = candidates.find((entry) => text(entry.last_run_id) && text(entry.last_run_id) === text(row.runId))
    ?? candidates.find((entry) => !text(entry.last_run_id));
  if (member) {
    const state = text(member.state);
    if (text(member.version_gap) || state === 'partial' || state === 'unknown') return 'version_gap';
    if (member.fresh !== true || state === 'stale') return 'stale';
    return 'fresh';
  }
  const finished = Date.parse(text(row.finishedAt) || text(row.startedAt));
  if (!Number.isFinite(finished)) return 'version_gap';
  return nowMs - finished > freshnessWindowMs(coverage) ? 'stale' : 'fresh';
}

const MEMBER_STATE_COPY = Object.freeze({
  fresh: Object.freeze({ label: 'Current, counted' }),
  stale: Object.freeze({ label: 'Stale, not counted' }),
  version_gap: Object.freeze({ label: 'Older check version, not counted' }),
});

/** Managed-rule markers that older coverage data may still roll into a custom-canary rollup. */
const MANAGED_MARKER_CHECK_IDS = Object.freeze(['waf.scanner_signature_marker.safe']);

function isManagedMarker(entry) {
  const item = record(entry);
  if (!item) return false;
  const scope = text(item.assuranceScope ?? item.assurance_scope ?? record(item.probe_profile)?.assurance_scope);
  return scope === MANAGED_SCOPE || text(item.rule_family ?? item.ruleFamily) === 'managed';
}

/** Custom canary rule members the server rolled up, each with its own freshness answer and the run it graded; managed markers are never members. */
export function customCanaryMembers(coverage, { checks = [] } = {}) {
  const managed = new Set(MANAGED_MARKER_CHECK_IDS);
  for (const check of list(checks)) {
    if (isManagedMarker(check)) managed.add(text(record(check)?.checkId ?? record(check)?.check_id));
  }
  const out = [];
  const seen = new Set();
  const rollups = [...list(record(coverage)?.custom_canary_rollups), ...list(record(coverage)?.pairs).filter((pair) => record(pair)?.custom_canary_rollup === true)];
  for (const rollup of rollups) {
    for (const raw of list(record(rollup)?.rolled_up_pairs)) {
      const member = record(raw);
      const checkId = text(member?.check_id);
      const runId = text(member?.last_run_id);
      const key = `${checkId}|${runId}`;
      if (!checkId || seen.has(key) || managed.has(checkId) || isManagedMarker(member)) continue;
      seen.add(key);
      const state = text(member.state);
      const evidence = text(member.version_gap) || state === 'partial' || state === 'unknown' ? 'version_gap' : member.fresh !== true || state === 'stale' ? 'stale' : 'fresh';
      out.push({ checkId, runId, verdict: text(member.verdict), observedAt: text(member.observed_at), evidence, ...MEMBER_STATE_COPY[evidence] });
    }
  }
  return out.sort((left, right) => left.checkId.localeCompare(right.checkId));
}

function ruleCategoryOf(row) {
  if (row.probeKind === 'waf_class_marker_probe') return row.assuranceScope === MANAGED_SCOPE ? `managed:${row.markerClass || row.checkId}` : 'custom_canary';
  if (row.probeKind === 'waf_evasion_marker_probe') return 'encoding_evasion';
  if (/rate_limit/.test(row.probeKind)) return 'rate_limiting';
  if (/method_policy/.test(row.probeKind)) return 'http_method_policy';
  return `${row.category?.id ?? 'other'}:${row.probeKind || row.checkId}`;
}

function emptyTally() {
  return { enforced: 0, notEnforced: 0, inconclusive: 0, ignored: 0, notRun: 0, total: 0 };
}

/** Roll marker rows up by distinct rule (marker class), so one rule never counts twice. */
function tallyRules(rows, keyOf, options) {
  const rules = new Map();
  for (const row of rows) {
    const key = keyOf(row);
    if (!rules.has(key)) rules.set(key, []);
    rules.get(key).push(row);
  }
  const tally = emptyTally();
  for (const members of rules.values()) {
    tally.total += 1;
    const states = members.map((row) => ({ row, evidence: rowEvidenceState(row, options) }));
    const fresh = states.filter((entry) => entry.evidence === 'fresh');
    if (fresh.some((entry) => entry.row.status === 'failed')) tally.notEnforced += 1;
    else if (fresh.some((entry) => entry.row.status === 'passed')) tally.enforced += 1;
    else if (states.some((entry) => ['stale', 'version_gap'].includes(entry.evidence))) tally.ignored += 1;
    else if (members.some((row) => row.status === 'inconclusive')) tally.inconclusive += 1;
    else tally.notRun += 1;
  }
  return { ...tally, tested: tally.enforced + tally.notEnforced };
}

/** WAF marker results split into managed rule markers, custom canary rules and evasion; null when nothing is recorded. */
export function wafRuleEnforcement(rows, options = {}) {
  const markers = list(rows).filter((row) => row?.readinessCapable === true && row.category?.id === 'waf');
  const managed = markers.filter((row) => row.probeKind === 'waf_class_marker_probe' && row.assuranceScope === MANAGED_SCOPE);
  const custom = markers.filter((row) => row.probeKind === 'waf_class_marker_probe' && row.assuranceScope !== MANAGED_SCOPE);
  const evasion = markers.filter((row) => row.probeKind === 'waf_evasion_marker_probe');
  const recorded = [...managed, ...custom, ...evasion].some((row) => RECORDED_RESULT_STATUSES.has(row.status));
  if (!recorded) return null;
  const lastAt = [...managed, ...custom, ...evasion]
    .filter((row) => RECORDED_RESULT_STATUSES.has(row.status))
    .map((row) => text(row.finishedAt || row.startedAt))
    .filter(Boolean)
    .sort()
    .at(-1) ?? '';
  return {
    managed: tallyRules(managed, (row) => row.markerClass || row.checkId, options),
    custom: tallyRules(custom, (row) => row.markerClass || row.checkId, options),
    evasion: tallyRules(evasion, (row) => row.checkId, options),
    lastAt,
  };
}

function shareSuffix(tally) {
  const parts = [];
  parts.push(`${tally.inconclusive} inconclusive`);
  if (tally.ignored) parts.push(`${tally.ignored} not counted (stale or older check version)`);
  if (tally.notRun) parts.push(`${tally.notRun} not run`);
  return parts.join(' · ');
}

/** "Managed rules enforced: 3 of 4 markers · 1 inconclusive" and the custom canary equivalent. */
export function wafRuleSentences(enforcement) {
  if (!enforcement) return [];
  const lines = [];
  const { managed, custom, evasion } = enforcement;
  if (managed.total) lines.push({ id: 'managed', label: 'Managed rules enforced', ratio: `${managed.enforced} of ${managed.tested} ${managed.tested === 1 ? 'marker' : 'markers'}`, detail: shareSuffix(managed), tally: managed });
  if (custom.total) lines.push({ id: 'custom', label: 'Custom canary rules enforced', ratio: `${custom.enforced} of ${custom.tested}`, detail: shareSuffix(custom), tally: custom });
  if (evasion.total && evasion.total - evasion.notRun > 0) lines.push({ id: 'evasion', label: 'Encoding tricks blocked', ratio: `${evasion.enforced} of ${evasion.tested}`, detail: shareSuffix(evasion), tally: evasion });
  return lines;
}

const EFFICACY_META = Object.freeze({
  protecting: { label: 'Protecting', tone: 'success' },
  partial: { label: 'Partially protecting', tone: 'warn' },
  mostly_exposed: { label: 'Mostly not protecting', tone: 'danger' },
  not_protecting: { label: 'Not protecting', tone: 'danger' },
  bypassable: { label: 'Bypassable via origin', tone: 'danger' },
  insufficient: { label: 'Not enough evidence', tone: 'muted' },
  present_unmeasured: { label: 'Detected · not measured yet', tone: 'info' },
  absent: { label: 'Not detected', tone: 'warn' },
  unknown: { label: 'Not evaluated yet', tone: 'muted' },
});

/** Only a fresh `exposed` verdict from an origin-lockdown check proves traffic can skip the edge. */
function originExposed(rows, options) {
  return list(rows).some((row) => ORIGIN_LOCKDOWN_CHECK_IDS.has(text(row?.checkId))
    && text(row.verdict).toLowerCase() === 'exposed'
    && rowEvidenceState(row, options) === 'fresh');
}

function inLayer(row, layer) {
  if (row?.readinessCapable !== true) return false;
  if (layer === 'waf') return row.category?.layer === 'waf';
  return row.category?.layer === 'cdn' && CDN_EFFICACY_CATEGORIES.has(row.category?.id);
}

function layerEfficacy(layer, rows, edge, exposed, options) {
  const family = record(edge?.[layer]);
  const familyStatus = text(family?.status);
  const layerRows = list(rows).filter((row) => inLayer(row, layer));
  const graded = layerRows.map((row) => ({ row, evidence: rowEvidenceState(row, options) }));
  const fresh = graded.filter((entry) => entry.evidence === 'fresh').map((entry) => entry.row);
  const ignored = graded.filter((entry) => ['stale', 'version_gap'].includes(entry.evidence)).length;
  const inconclusive = layerRows.filter((row) => row.status === 'inconclusive').length;
  let passed = fresh.filter((row) => row.status === 'passed').length;
  let failed = fresh.length - passed;
  let basis = 'checks';
  const ruleCategories = new Set(fresh.map(ruleCategoryOf)).size;
  const effectiveness = record(edge?.effectiveness);
  if (layer === 'waf' && fresh.length === 0 && Number(effectiveness?.tested_count) > 0) {
    // The fingerprint scan's own markers are context only; they can never make a layer "Protecting".
    passed = Number(effectiveness.blocked_count) || 0;
    failed = Number(effectiveness.passed_count) || 0;
    basis = 'fingerprint_markers';
  }
  const tested = passed + failed;
  let status;
  if (basis === 'fingerprint_markers') status = 'insufficient';
  else if (tested === 0) {
    if (inconclusive || ignored) status = 'insufficient';
    else status = familyStatus === 'detected' ? 'present_unmeasured' : familyStatus === 'not_detected' ? 'absent' : 'unknown';
  } else if (exposed) status = 'bypassable';
  else if (failed > 0 && passed === 0) status = 'not_protecting';
  // Blocking a minority of what was tested is not "partial" protection in any useful sense.
  else if (failed > 0) status = passed / tested < 0.5 ? 'mostly_exposed' : 'partial';
  else if (tested < EFFICACY_MINIMUM.concluded || ruleCategories < EFFICACY_MINIMUM.ruleCategories) status = 'insufficient';
  else status = 'protecting';
  return {
    layer,
    status,
    ...EFFICACY_META[status],
    detected: familyStatus,
    provider: text(family?.provider ?? family?.vendor),
    passed,
    failed,
    tested,
    inconclusive,
    ignored,
    ruleCategories: basis === 'checks' ? ruleCategories : 0,
    score: tested && basis === 'checks' ? Math.round((passed / tested) * 100) : null,
    basis,
    originExposed: exposed,
    exposedChecks: fresh.filter((row) => row.status === 'failed').map((row) => row.name),
  };
}

/** WAF and CDN efficacy from fresh, current-version verdicts only; DNS and network results never count toward the CDN. */
export function assessEdgeEfficacy({ rows = [], edge = null, coverage = null, nowMs = Date.now() } = {}) {
  const options = { coverage, nowMs };
  const exposed = originExposed(rows, options);
  return { waf: layerEfficacy('waf', rows, edge, exposed, options), cdn: layerEfficacy('cdn', rows, edge, exposed, options), originExposed: exposed };
}

function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many}`;
}

export function efficacySentence(efficacy) {
  const thing = efficacy.layer === 'waf' ? 'WAF checks' : 'edge checks';
  const share = [`${efficacy.inconclusive} inconclusive`, efficacy.ignored ? `${efficacy.ignored} not counted (stale or older check version)` : ''].filter(Boolean).join(' · ');
  if (efficacy.status === 'unknown') return 'No evidence yet. Run the checks to measure it.';
  if (efficacy.status === 'absent') return `No ${efficacy.layer === 'waf' ? 'WAF' : 'CDN'} was detected in front of this domain, and no check has measured blocking yet.`;
  if (efficacy.status === 'present_unmeasured') return 'Detected in front of this domain, but no check has tested whether it blocks anything. Run the checks to measure it.';
  if (efficacy.basis === 'fingerprint_markers') {
    return `Only the fingerprint scan has run: ${efficacy.passed} of ${efficacy.tested} of its markers were blocked. That is context, not proof. Run the WAF checks to measure enforcement.`;
  }
  if (efficacy.status === 'insufficient') {
    return `Not enough evidence: ${plural(efficacy.tested, 'fresh concluded check', 'fresh concluded checks')} across ${plural(efficacy.ruleCategories, 'rule category', 'rule categories')}; at least ${EFFICACY_MINIMUM.concluded} across ${EFFICACY_MINIMUM.ruleCategories} are needed. ${share}.`;
  }
  const ratio = `Held on ${efficacy.passed} of ${efficacy.tested} fresh concluded ${thing} · ${share}`;
  if (efficacy.status === 'bypassable') return `${ratio}. A fresh origin-lockdown check found your origin answering directly, so traffic can go around the edge.`;
  if (efficacy.status === 'protecting') return `${ratio}.`;
  return `${ratio}. ${plural(efficacy.failed, 'check', 'checks')} reached your application.`;
}

const SOURCE_COPY = Object.freeze({
  response_header: { method: 'HTTP response header', detail: 'An edge platform header in the HTTP response matched this provider.' },
  response_fingerprint: { method: 'WAF fingerprint', detail: 'AstraNull matched benign probe responses against this WAF\'s fingerprint.' },
  address_range: { method: 'IP address range', detail: 'A resolved address sits inside this provider\'s published network range.' },
  cname_suffix: { method: 'DNS CNAME', detail: 'The domain\'s CNAME chain points into this provider\'s edge.' },
  asn_lookup: { method: 'ASN / Network routing', detail: 'A resolved address belongs to this provider\'s autonomous system (ASN).' },
  corroborated_generic_behavior: { method: 'Block behavior', detail: 'Benign attack markers were blocked with a WAF-style response; the vendor is unknown.' },
  legacy_provider_summary: { method: 'Earlier detection', detail: 'Recorded by an earlier detection run.' },
  edge_fingerprint: { method: 'Edge signature', detail: 'External probe evidence matched this provider\'s edge signature.' },
});

/** Display name for a provider code. */
export function providerName(code, displayName = '') {
  const known = {
    cloudflare: 'Cloudflare', akamai: 'Akamai', cloudfront: 'Amazon CloudFront', amazon: 'Amazon', aws: 'AWS', awswaf: 'AWS WAF',
    azure: 'Microsoft Azure', azure_front_door: 'Azure Front Door', fastly: 'Fastly', gcp: 'Google Cloud', google: 'Google Cloud',
    incapsula: 'Imperva (Incapsula)', imperva: 'Imperva', sucuri: 'Sucuri', stackpath: 'StackPath', vercel: 'Vercel', netlify: 'Netlify',
    bunnycdn: 'Bunny CDN', keycdn: 'KeyCDN', gcore: 'Gcore', cdn77: 'CDN77', modsecurity: 'ModSecurity', generic: 'Unidentified WAF',
    hetzner: 'Hetzner', digitalocean: 'DigitalOcean', ovh: 'OVHcloud', vultr: 'Vultr', linode: 'Linode', scaleway: 'Scaleway',
    leaseweb: 'Leaseweb', contabo: 'Contabo', hostinger: 'Hostinger', upcloud: 'UpCloud', equinix: 'Equinix Metal', oracle: 'Oracle Cloud',
    cachefly: 'CacheFly', edgecast: 'Edgecast',
  };
  return known[text(code).toLowerCase()] ?? (text(displayName) || titleCase(code) || 'Unknown provider');
}

/** Brand mark id for the provider-logo component, or '' when no accurate mark exists. */
export function providerLogoId(code) {
  const key = text(code).toLowerCase();
  if (key === 'cloudflare') return 'cloudflare';
  if (key === 'akamai') return 'akamai';
  if (['aws', 'amazon', 'cloudfront', 'awswaf'].includes(key)) return 'route53';
  if (key.startsWith('azure')) return 'azure';
  if (['gcp', 'google'].includes(key)) return 'google_cloud';
  return '';
}

/**
 * "How we found out": one entry per detected layer with every independent source that agreed,
 * plus the raw DNS/fingerprint facts behind it. Signal labels and provider names only.
 */
export function edgeEvidenceSignals(edge) {
  const presented = record(edge);
  if (!presented) return { layers: [], facts: [] };
  const evidence = record(presented.evidence) ?? {};
  const vendorMatches = list(evidence.vendor_matches);
  const wafw00f = record(evidence.waf_fingerprint) ?? record(evidence.wafw00f);
  const cdncheck = record(evidence.edge_classifier) ?? record(evidence.cdncheck);
  const layers = list(presented.layers).map((raw) => {
    const layer = record(raw) ?? {};
    const family = text(layer.family);
    const provider = text(layer.provider);
    const matched = vendorMatches.find((match) => text(record(match)?.vendor) === provider);
    const signals = list(record(matched)?.matched_signals).map((signal) => text(record(signal)?.signal)).filter(Boolean);
    // Only sources and signals the server recorded for this layer. Nothing is inferred from
    // another family's evidence, and a missing method stays "Source not recorded".
    const sources = list(layer.sources).map(text).filter(Boolean);
    const resolvedSignals = [...signals];
    const sourceObjects = sources.map((source) => ({
      id: text(source),
      ...(SOURCE_COPY[text(source)] ?? { method: titleCase(source), detail: '' }),
    }));
    const evidenceSummary = sourceObjects.map((s) => s.method).join(' · ');
    return {
      family,
      provider,
      name: providerName(provider, layer.display_name),
      logo: providerLogoId(provider),
      confidence: Number.isFinite(Number(layer.confidence)) ? Math.round(Number(layer.confidence) * 100) : null,
      agreement: text(layer.evidence_consistency),
      conflicting: layer.conflicting === true,
      sources: sourceObjects,
      signals: [...new Set(resolvedSignals)].slice(0, 6),
      evidenceSummary,
    };
  });
  const facts = [];
  const chain = list(evidence.dns_cname_chain ?? presented.dns_cname_chain).map(text).filter(Boolean);
  if (chain.length) facts.push({ id: 'cname', label: 'CNAME chain', value: chain.join(' → ') });
  const ips = list(evidence.dns_resolved_ips ?? presented.dns_resolved_ips).map(text).filter(Boolean);
  if (ips.length) facts.push({ id: 'ips', label: 'Resolved addresses', value: ips.slice(0, 6).join(', ') });
  const asn = record(evidence.asn);
  if (asn && (asn.asn || asn.org)) {
    facts.push({
      id: 'asn',
      label: 'Network / ASN',
      value: `AS${asn.asn}${asn.name || asn.org ? ` · ${asn.name || asn.org}` : ''}`,
    });
  }
  if (wafw00f) {
    const firewall = text(wafw00f.firewall);
    facts.push({
      id: 'waf_fingerprint',
      label: 'AstraNull WAF fingerprint',
      value: wafw00f.detected === true && firewall && firewall !== 'None'
        ? `${firewall}${text(wafw00f.manufacturer) && text(wafw00f.manufacturer) !== 'None' ? ` (${text(wafw00f.manufacturer)})` : ''}`
        : record(wafw00f.generic)?.found === true ? 'Generic WAF behavior detected' : 'No WAF plugin matched',
    });
  }
  if (cdncheck) {
    facts.push({
      id: 'edge_classifier',
      label: 'AstraNull edge classifier',
      value: cdncheck.matched === true
        ? `${providerName(cdncheck.provider)}${text(cdncheck.item_type) ? ` · ${text(cdncheck.item_type).toUpperCase()}` : ''}${text(cdncheck.source) ? ` via ${text(cdncheck.source)}` : ''}`
        : 'No CDN range or CNAME matched',
    });
  }
  const effectiveness = record(presented.effectiveness);
  if (Number(effectiveness?.tested_count) > 0) {
    facts.push({ id: 'markers', label: 'Benign markers', value: `${Number(effectiveness.blocked_count) || 0} of ${Number(effectiveness.tested_count)} blocked during the fingerprint scan` });
  }
  return { layers, facts };
}

/**
 * Edge detection phase for the hero card. `localRequest` is the page's own in-flight request
 * (pending, blocked, error) so the card says "Evaluating" the moment detection is queued.
 */
export function edgeDetectionPhase({ eligible, edge, request = null, localRequest = '', scanFingerprintActive = false } = {}) {
  if (localRequest === 'pending' || scanFingerprintActive) return 'evaluating';
  if (localRequest === 'blocked') return 'waiting';
  if (localRequest === 'error') return 'error';
  if (ACTIVE_RUN_STATUSES.has(text(record(request)?.run_status).toLowerCase())) return 'evaluating';
  if (record(edge)) return text(edge.status) || 'inconclusive';
  if (!eligible) return 'locked';
  if (record(request)) return 'no_result';
  return 'not_started';
}

/**
 * Should the page queue edge detection on its own? Only for a freshly onboarded domain (no run
 * of any kind yet), and never before ownership is proven. Older targets get a Detect button.
 */
export function shouldAutoDetectEdge({ eligible, featureEnabled, canRun, edge, request, scanActive, attempted, hasPriorRuns }) {
  return Boolean(eligible && featureEnabled && canRun && !hasPriorRuns && !record(edge) && !record(request) && !scanActive && !attempted);
}

export function validationScansPathForTarget(targetId) {
  const params = new URLSearchParams({ target_id: text(targetId), limit: '1' });
  return `/v1/validation-scans?${params.toString()}`;
}

/** Provider families shown on a target, each from its own source only. */
export const PROVIDER_FAMILY_ORDER = Object.freeze(['cdn', 'waf', 'cloud', 'origin_hosting', 'dns']);

const FAMILY_TITLES = Object.freeze({
  cdn: 'CDN',
  waf: 'WAF',
  cloud: 'Edge or cloud layer',
  origin_hosting: 'Origin hosting',
  dns: 'DNS provider',
});

const FAMILY_STATUS = Object.freeze({
  detected: { label: 'Detected', tone: 'default' },
  not_detected: { label: 'Not detected in this observation', tone: 'muted' },
  inconclusive: { label: 'Inconclusive', tone: 'warn' },
  not_checked: { label: 'Not checked', tone: 'muted' },
  not_recorded: { label: 'Not recorded', tone: 'muted' },
  unknown: { label: 'Unknown', tone: 'muted' },
  error: { label: 'Attempt failed', tone: 'warn' },
  attempt_failed: { label: 'Attempt failed', tone: 'warn' },
});

const FAMILY_LIMITS = Object.freeze({
  cdn: 'Presence of a CDN does not prove capacity or blocking.',
  waf: 'Detection is not effectiveness; blocking comes from check results.',
  cloud: 'An observed edge or cloud address does not identify where the origin is hosted.',
  origin_hosting: 'Origin hosting is never inferred from CDN, WAF, or edge addressing.',
  dns: 'The DNS provider is never inferred from CDN or WAF vendors.',
});

function finiteOrNull(value) {
  const number = Number(value);
  return value === null || value === undefined || value === '' || !Number.isFinite(number) ? null : number;
}

/**
 * One row per provider family. Uses `protection_profile.families[family]` when the server sends
 * it; otherwise only the legacy `edge_detection[family]` row of the same family (WAF, CDN, edge
 * or cloud). DNS and origin hosting stay Unknown without their own recorded source. A WAF vendor
 * never fills the CDN row, and sources are listed only when recorded.
 */
export function providerFamilyRows({ protection_profile: profile = null, edge_detection: edge = null } = {}) {
  const families = record(record(profile)?.families);
  const edgeRecord = record(edge);
  return PROVIDER_FAMILY_ORDER.map((family) => {
    const fromProfile = record(families?.[family]);
    let row = fromProfile;
    let source = fromProfile ? 'protection_profile' : 'none';
    let layer = null;
    if (!row && edgeRecord && ['waf', 'cdn', 'cloud'].includes(family)) {
      row = record(edgeRecord[family]);
      layer = list(edgeRecord.layers).map(record).find((entry) => entry && text(entry.family) === family) ?? null;
      source = row ? 'edge_detection' : 'none';
    }
    let status = text(row?.status).toLowerCase();
    if (!status) {
      if (family === 'dns' || family === 'origin_hosting') status = 'unknown';
      else status = edgeRecord ? 'not_recorded' : 'not_checked';
    }
    const provider = text(row?.provider) || text(row?.vendor) || (source === 'edge_detection' ? text(layer?.provider) : '');
    const meta = FAMILY_STATUS[status] ?? { label: titleCase(status) || 'Unknown', tone: 'muted' };
    const sources = list(row?.sources ?? layer?.sources).map(text).filter(Boolean).map((id) => ({
      id,
      ...(SOURCE_COPY[id] ?? { method: titleCase(id), detail: '' }),
    }));
    const confidence = finiteOrNull(row?.confidence ?? layer?.confidence);
    const freshness = text(row?.freshness);
    return {
      family,
      title: FAMILY_TITLES[family],
      status,
      statusLabel: meta.label,
      tone: freshness === 'stale' && status === 'detected' ? 'warn' : meta.tone,
      provider,
      providerName: provider ? providerName(provider, row?.display_name ?? layer?.display_name) : '',
      logo: provider ? providerLogoId(provider) : '',
      observedAt: text(row?.observed_at) || (source === 'edge_detection' ? text(edgeRecord?.observed_at) : ''),
      testRunId: text(row?.test_run_id) || (source === 'edge_detection' ? text(edgeRecord?.test_run_id) : ''),
      freshness: freshness || (source === 'none' ? 'unknown' : ''),
      sources,
      confidence: confidence === null ? null : Math.round(confidence * (confidence <= 1 ? 100 : 1)),
      reason: text(row?.reason),
      limitation: FAMILY_LIMITS[family],
      source,
    };
  });
}

/**
 * Recorded marker effectiveness, separate from detection. Percentage is null whenever the
 * definitive denominator is zero; nothing is computed from provider presence.
 */
export function markerEffectiveness({ protection_profile: profile = null, edge_detection: edge = null } = {}) {
  const fromProfile = record(record(profile)?.effectiveness);
  const legacy = record(record(edge)?.effectiveness);
  const row = fromProfile ?? legacy;
  if (!row) return null;
  const blocked = finiteOrNull(row.blocked_count);
  const allowed = finiteOrNull(row.allowed_count ?? row.passed_count);
  const inconclusive = finiteOrNull(row.inconclusive_count);
  const notRun = finiteOrNull(row.not_run_count);
  const definitive = (blocked ?? 0) + (allowed ?? 0);
  const tested = finiteOrNull(row.tested_count);
  if (definitive === 0 && !inconclusive && !tested) return null;
  const percentage = definitive > 0 ? finiteOrNull(row.percentage) : null;
  return {
    blocked: blocked ?? 0,
    allowed: allowed ?? 0,
    inconclusive: inconclusive ?? 0,
    notRun,
    definitive,
    percentage,
    source: fromProfile ? 'protection_profile' : 'edge_detection',
  };
}

/**
 * Origin reachability as the profile records it. `assurance` stays what the server says (`none`
 * today): a recorded reachability observation is not an authorized origin lockdown.
 */
export function originExposureDetail({ protection_profile: profile = null } = {}) {
  const origin = record(record(profile)?.origin);
  const reach = record(origin?.reachability);
  return {
    status: text(origin?.status) || 'not_tested',
    assurance: text(origin?.assurance) || 'not_recorded',
    reachabilityStatus: text(reach?.status) || 'not_tested',
    testedTargetId: text(reach?.tested_target_id),
    scenarioId: text(reach?.scenario_id),
    source: text(reach?.source),
    limitations: list(reach?.limitations).map(text).filter(Boolean),
  };
}

/** Origin exposure: only an explicit recorded status; the legacy not_exposed default is ignored. */
export function originExposureStatus({ protection_profile: profile = null } = {}) {
  const origin = record(record(profile)?.origin);
  const status = text(origin?.status);
  return status || 'not_tested';
}

const TAB_ALIASES = Object.freeze({
  overview: 'overview',
  protection: 'overview',
  edge: 'overview',
  profile: 'overview',
  validate: 'validate',
  checks: 'validate',
  run: 'validate',
  findings: 'findings',
  subdomains: 'subdomains',
  history: 'history',
  changes: 'history',
  runs: 'history',
  controls: 'controls',
  declarations: 'controls',
  coverage: 'coverage',
  'rule-coverage': 'coverage',
});

/** Unified target tabs; legacy names (protection, edge, runs, checks) keep resolving. */
export function targetTabFromParam(value) {
  return TAB_ALIASES[text(value).toLowerCase()] ?? 'overview';
}

const HOST_KINDS = new Set(['fqdn', 'hostname', 'domain', 'url', 'dns_zone', 'canary']);

/**
 * Normalized hostname identity for one declared target, or '' when the target is not a hostname
 * (IP, CIDR, TCP endpoint). Lowercased, trailing dot removed; URL targets reduce to their host.
 */
export function normalizedHostKey(target) {
  const kind = text(target?.kind).toLowerCase();
  if (!HOST_KINDS.has(kind)) return '';
  let value = text(target?.value).toLowerCase();
  if (!value) return '';
  if (kind === 'url' || value.includes('://')) {
    try {
      value = new URL(value.includes('://') ? value : `https://${value}`).hostname;
    } catch {
      return '';
    }
  }
  value = value.replace(/\.$/, '');
  if (/^[0-9.]+$/.test(value) || value.includes(':')) return '';
  return value;
}

/** Declared-record count versus distinct hostname count; the two units are never merged. */
export function inventoryUnits(targets) {
  const hosts = new Set();
  let nonHost = 0;
  for (const target of list(targets)) {
    const key = normalizedHostKey(target);
    if (key) hosts.add(key);
    else nonHost += 1;
  }
  return { records: list(targets).length, distinctHosts: hosts.size, nonHostRecords: nonHost };
}

export const SERVICE_ROLES = Object.freeze(['website', 'api', 'login', 'dns', 'network']);
export const CRITICALITY_VALUES = Object.freeze(['critical', 'high', 'medium', 'low']);

/** Editable draft from the server declaration; inherited owner/criticality stay empty (not copied). */
export function declarationDraftFrom(declaration) {
  const source = record(declaration) ?? {};
  const owner = record(source.owner);
  const criticality = record(source.criticality);
  const criticalityValue = text(criticality?.value).toLowerCase();
  return {
    purpose: text(source.purpose),
    service_roles: list(source.service_roles).map((role) => text(role).toLowerCase()).filter((role) => SERVICE_ROLES.includes(role)),
    owner_label: text(owner?.status) === 'declared' ? text(owner?.label) : '',
    criticality: text(criticality?.status) === 'declared' && CRITICALITY_VALUES.includes(criticalityValue) ? criticalityValue : '',
  };
}

/**
 * Only changed fields. An explicit null or [] clears the target value and blocks group
 * inheritance, so untouched inherited fields are never sent.
 */
export const DECLARATION_LIMITS = Object.freeze({ purpose: 200, owner_label: 80 });

/** Field errors for a draft; values are never cropped to fit, the user fixes them. */
export function validateDeclarationDraft(draft) {
  const errors = {};
  if (text(draft.purpose).length > DECLARATION_LIMITS.purpose) errors.purpose = `Purpose must be at most ${DECLARATION_LIMITS.purpose} characters.`;
  if (text(draft.owner_label).length > DECLARATION_LIMITS.owner_label) errors.owner_label = `Owner must be at most ${DECLARATION_LIMITS.owner_label} characters.`;
  return errors;
}

export function declarationPatchBody(initial, draft) {
  const patch = {};
  if (text(draft.purpose) !== text(initial.purpose)) patch.purpose = text(draft.purpose) || null;
  if ([...draft.service_roles].sort().join(',') !== [...initial.service_roles].sort().join(',')) patch.service_roles = [...draft.service_roles];
  if (text(draft.owner_label) !== text(initial.owner_label)) patch.owner = text(draft.owner_label) ? { label: text(draft.owner_label) } : null;
  if (draft.criticality !== initial.criticality) patch.criticality = draft.criticality || null;
  return patch;
}

/*
 * Declared-host cohorts (GET /v1/analytics/declared-hosts and filtered GET /v1/targets share one
 * server predicate). The browser never computes a cohort; it carries the server's exact filters.
 */

/** Server-allowlisted cohort filters. Aliases map to their canonical key. */
export const COHORT_FILTER_KEYS = Object.freeze([
  'q', 'target_group_id', 'verification_state', 'kind', 'tag', 'service_role', 'criticality',
  'owner_status', 'owner', 'family', 'family_status', 'freshness', 'has_open_finding', 'unit',
]);
const COHORT_ALIASES = Object.freeze({ search: 'q', group: 'target_group_id', target_group: 'target_group_id', verification: 'verification_state', role: 'service_role' });
const UNIT_TOKENS = Object.freeze({ hostname: 'hostname', normalized_hostname: 'hostname', target: 'target', declared_target: 'target' });
const COHORT_VALUE = /^[A-Za-z0-9_.:@ /+-]{1,120}$/;

/**
 * Canonical cohort filters from address or server parameters. Aliases fold into canonical keys;
 * a conflicting alias is dropped (the server would reject it); unknown keys never pass.
 * Returns null when no cohort filter is present.
 */
export function canonicalCohortFilters(input) {
  const entries = input instanceof URLSearchParams ? [...input.entries()] : Object.entries(record(input) ?? {});
  const out = {};
  const aliasValues = {};
  for (const [rawKey, rawValue] of entries) {
    const value = text(rawValue);
    if (!value || !COHORT_VALUE.test(value)) continue;
    if (COHORT_FILTER_KEYS.includes(rawKey)) out[rawKey] = value;
    else if (COHORT_ALIASES[rawKey]) aliasValues[COHORT_ALIASES[rawKey]] = value;
  }
  for (const [key, value] of Object.entries(aliasValues)) {
    if (!out[key]) out[key] = value;
  }
  if (out.unit) {
    const unit = UNIT_TOKENS[out.unit];
    if (unit) out.unit = unit;
    else delete out.unit;
  }
  if ((out.family_status || out.freshness) && !out.family) {
    delete out.family_status;
    delete out.freshness;
  }
  const keys = Object.keys(out).filter((key) => key !== 'unit');
  return keys.length ? out : null;
}

/** Targets address for a server `list_query` (or `list_query.query`), keeping only allowed filters and the unit. */
export function cohortHrefFromListQuery(listQuery) {
  const source = record(record(listQuery)?.query) ?? record(listQuery) ?? {};
  const filters = canonicalCohortFilters(source) ?? {};
  if (source.unit && UNIT_TOKENS[text(source.unit)]) filters.unit = UNIT_TOKENS[text(source.unit)];
  const params = new URLSearchParams();
  for (const key of COHORT_FILTER_KEYS) {
    if (filters[key]) params.set(key, filters[key]);
  }
  const query = params.toString();
  return query ? `#targets?${query}` : '#targets';
}

const SEGMENT_LABELS = Object.freeze({
  detected: 'Detected',
  not_detected: 'Not detected in the last observation',
  inconclusive: 'Inconclusive',
  conflict: 'Conflicting signals',
  stale: 'Stale observation',
  not_checked: 'Not checked',
  not_recorded: 'Not recorded',
  unknown: 'Unknown',
});
const SEGMENT_GROUP = Object.freeze({
  detected: 'detected',
  not_detected: 'not_detected',
  inconclusive: 'inconclusive',
  conflict: 'conflict',
  stale: 'stale',
  not_checked: 'unmeasured',
  not_recorded: 'unmeasured',
  unknown: 'unmeasured',
});

/**
 * Display buckets for one family from the analytics response. The server's `unknown_count` is the
 * unknown bucket only; "Unknown or not checked" adds the explicit not_checked and not_recorded
 * segments to it, while each part keeps its own exact list link. Inconclusive and conflict stay
 * separate. `reconciled` is false when the parts do not add up to the denominator.
 */
export function familyCoverageBuckets(payload) {
  const body = record(payload) ?? {};
  const denominator = finiteOrNull(body.denominator);
  const parts = list(body.segments).map(record).filter((segment) => segment && text(segment.key)).map((segment) => ({
    key: text(segment.key),
    label: SEGMENT_LABELS[text(segment.key)] ?? titleCase(segment.key),
    group: SEGMENT_GROUP[text(segment.key)] ?? 'other',
    count: finiteOrNull(segment.count) ?? 0,
    href: cohortHrefFromListQuery(segment.list_query),
  }));
  const unknownCount = finiteOrNull(body.unknown_count);
  if (unknownCount !== null) {
    const family = text(record(record(body.list_query)?.query)?.family ?? record(body.filters)?.family);
    const unit = text(record(record(body.list_query)?.query)?.unit ?? body.canonical_unit);
    parts.push({
      key: 'unknown',
      label: SEGMENT_LABELS.unknown,
      group: 'unmeasured',
      count: unknownCount,
      href: cohortHrefFromListQuery({ family, unit, family_status: 'unknown' }),
    });
  }
  const unmeasured = parts.filter((part) => part.group === 'unmeasured').reduce((sum, part) => sum + part.count, 0);
  const total = parts.reduce((sum, part) => sum + part.count, 0);
  return {
    denominator,
    parts,
    unmeasured,
    reconciled: denominator !== null && total === denominator,
    units: {
      targetRecords: finiteOrNull(record(body.units)?.target_records),
      normalizedHosts: finiteOrNull(record(body.units)?.normalized_hosts),
    },
    unit: text(body.canonical_unit) || UNIT_TOKENS[text(body.unit)] || '',
    asOf: text(body.as_of),
    current: text(body.scope) === 'current' && body.historical === false,
    complete: body.complete !== false,
  };
}

/**
 * What to do with a failed cohort page read. `refetch` drops cohort_version and cursor but keeps
 * every visible filter; `reset` returns to the first page with the same filters.
 */
export function classifyCohortError(error) {
  const status = Number(record(error)?.status);
  const code = text(record(record(error)?.payload)?.error);
  if (status === 409 && code === 'cohort_changed') return { action: 'refetch', reason: 'cohort_changed' };
  if (status === 409 && (code === 'cursor_clock_mismatch' || code === 'cursor_filter_mismatch')) return { action: 'reset', reason: code };
  if (status === 400 && code === 'invalid_cursor') return { action: 'reset', reason: code };
  if (status === 400) return { action: 'unsupported', reason: code || 'invalid_query' };
  if (status === 403) return { action: 'denied', reason: 'forbidden' };
  return { action: 'error', reason: code || 'unavailable' };
}

const ORIGIN_PROTECTED_KINDS = new Set(['fqdn', 'hostname', 'domain']);
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function hostOfTarget(target) {
  const kind = text(target?.kind).toLowerCase();
  const value = text(target?.value);
  if (kind === 'url') {
    try {
      return new URL(value).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch {
      return '';
    }
  }
  return value.replace(/\.$/, '').toLowerCase();
}

function isIpLiteral(host) {
  return IPV4.test(host) || host.includes(':');
}

/**
 * Which side of an origin relation a declared target can take, mirroring the server's binding
 * rule: a hostname or non-IP URL is `protected`, an IP target or IP-literal URL is `origin`.
 * Anything else (CIDR, TCP endpoint, zone) takes no part.
 */
export function originBindingRole(target) {
  const kind = text(target?.kind).toLowerCase();
  const host = hostOfTarget(target);
  if (!host) return null;
  if (kind === 'ip' || (kind === 'url' && isIpLiteral(host))) return 'origin';
  if (ORIGIN_PROTECTED_KINDS.has(kind) || (kind === 'url' && !isIpLiteral(host))) return 'protected';
  return null;
}

/** Catalog compatibility for a relation review, not readiness credit or runtime authorization. */
export function originRelationCheckEligible(check, target, pair) {
  return Boolean(record(check) && record(target) && record(pair)
    && text(target.id) && text(pair.target_id) === text(target.id)
    && text(check.check_id) && text(pair.check_id) === text(check.check_id)
    && text(pair.mechanism) === 'host_sni_bypass'
    && check.probe_profile?.kind === 'host_sni_bypass'
    && !checkExclusionReason(check)
    && check.mechanism_supported !== false && check.probe_profile.delivery_supported !== false
    && Array.isArray(check.supported_targets) && check.supported_targets.length > 0
    && checkSupportsTarget(check, target));
}

const ORIGIN_PROOF_STATES = new Set(['dns_verified', 'user_confirmed']);

function verificationStateOf(target) {
  return text(target?.verification_state) || text(record(target?.verification)?.state) || text(target?.verify_state);
}

/**
 * Declared origin targets that can be bound to `protectedTarget`. Only existing targets in the
 * loaded inventory are offered; nothing is discovered. `ready` have current origin proof
 * (dns_verified or user_confirmed); `blocked` exist but lack it.
 */
export function originBindingCandidates(targets, protectedTarget) {
  const selfId = text(protectedTarget?.id);
  const ready = [];
  const blocked = [];
  for (const target of list(targets)) {
    if (!record(target) || text(target.id) === selfId || target.deleted_at) continue;
    if (originBindingRole(target) !== 'origin') continue;
    const state = verificationStateOf(target) || 'unverified';
    (ORIGIN_PROOF_STATES.has(state) ? ready : blocked).push({ id: text(target.id), value: text(target.value), kind: text(target.kind), state });
  }
  return { ready, blocked };
}

const ORIGIN_BINDING_ERRORS = Object.freeze({
  ownership_not_verified: 'Ownership is not currently verified for this pair, so the relation was not recorded.',
  origin_target_not_verified_address: 'The origin must be a declared IP target or a URL whose host is an IP address.',
  protected_target_not_hostname: 'Only a hostname or a non-IP URL can be the protected side of a relation.',
  scope_mismatch: 'The port or path is outside what this target declares.',
  port_unspecified: 'This target declares several ports. Choose one of them.',
  path_unspecified: 'This target declares several paths. Choose one of them.',
  declaration_scope_invalid: 'The target declaration scope does not match its own hostname. Fix the declaration first.',
  unknown_target: 'One of these targets is no longer declared in this workspace.',
  binding_target_mismatch: 'A target cannot be bound to itself, and an origin check must run on the bound origin.',
  scope_not_declared: 'Undeclared destinations are not accepted.',
  unknown_origin_binding: 'This relation no longer exists or was archived.',
  already_archived: 'This relation is already archived.',
  origin_check_not_approved: 'Only the approved origin check can use a relation.',
  forbidden: 'Your role cannot change origin relations.',
  scope_conflict: 'These two targets already have an active relation with a different port or path. Nothing was changed. Archive that relation first if this scope should replace it.',
});

/** Server error code of an origin relation request, '' when none. */
export function originBindingErrorCode(error) {
  return text(record(record(error)?.payload)?.error) || text(record(error)?.error);
}

export function originBindingErrorMessage(error) {
  const code = originBindingErrorCode(error);
  const message = ORIGIN_BINDING_ERRORS[code] ?? (error instanceof Error && error.message ? error.message : 'The request did not complete.');
  const existing = code === 'scope_conflict' ? text(record(record(error)?.payload)?.existing_id) || text(record(error)?.existing_id) : '';
  return existing ? `${message} Existing relation: ${existing}.` : message;
}

/** Optional binding scope choice; empty fields are omitted so the server derives them from the declaration. */
export function originBindingScope({ port = '', path = '' } = {}) {
  const scope = {};
  const errors = {};
  const portText = text(port);
  if (portText) {
    const value = Number(portText);
    if (!/^\d+$/.test(portText) || value < 1 || value > 65535) errors.port = 'Enter a port from 1 to 65535.';
    else scope.port = value;
  }
  const pathText = text(path);
  if (pathText) {
    if (!pathText.startsWith('/') || pathText.length > 200 || /\s/.test(pathText)) errors.path = 'Enter a path that starts with / (up to 200 characters, no spaces).';
    else scope.path = pathText;
  }
  return { scope, errors, valid: Object.keys(errors).length === 0 };
}

const OUTCOME_LABELS = Object.freeze({
  detected: 'Detected',
  not_detected: 'Not detected',
  pass: 'Passed',
  fail: 'Gap found',
  reachable: 'Origin reachable',
  unreachable: 'Origin not reachable',
  timeout: 'Timed out',
  tls_failure: 'TLS failure',
  dns_failure: 'DNS failure',
  transport_failure: 'Transport failure',
  source_disconnected: 'Source disconnected',
  inconclusive: 'Inconclusive',
  canceled: 'Cancelled',
  cancelled: 'Cancelled',
  stale: 'Stale',
  error: 'Error',
  pending: 'Pending',
});

const ATTEMPT_LABELS = Object.freeze({
  successful: 'Completed observation',
  failed_attempt: 'Failed attempt',
  retained_noncurrent: 'Kept, not current',
});

const PRODUCER_LABELS = Object.freeze({
  signed_probe: 'Signed external probe',
  live_external: 'Live external probe',
  internal_simulation: 'Internal simulation',
  customer_declaration: 'Customer declaration',
  manual: 'Manual record',
});

const LIVE_PRODUCERS = new Set(['signed_probe', 'live_external']);

/** One observation as `/v1/targets/:id/observations` projects it, with plain labels. Nothing is inferred. */
export function presentObservation(item) {
  const row = record(item);
  if (!row || !text(row.id)) return null;
  const outcome = text(row.outcome);
  const attempt = text(row.attempt_class);
  const producer = text(row.producer_kind);
  return {
    id: text(row.id),
    family: text(row.family),
    outcome,
    outcomeLabel: OUTCOME_LABELS[outcome] ?? titleCase(outcome || 'not_recorded'),
    attempt,
    attemptLabel: ATTEMPT_LABELS[attempt] ?? titleCase(attempt || 'not_recorded'),
    producer,
    producerLabel: PRODUCER_LABELS[producer] ?? (producer ? titleCase(producer) : 'Not recorded'),
    live: producer ? LIVE_PRODUCERS.has(producer) : null,
    observedAt: text(row.observed_at),
    completedAt: text(row.source_completed_at),
    checkId: text(row.check_id),
    testRunId: text(row.test_run_id),
    sourceKind: text(row.source_kind),
    corpusVersion: text(row.corpus_version),
    scenarioVersion: text(row.scenario_version),
    checkVersion: text(row.check_version),
    bindingId: text(row.origin_binding_id),
  };
}

const COMPARISON_REASONS = Object.freeze({
  missing_observation: 'Only one completed observation is recorded.',
  transport_failure: 'One side is a failed attempt, which is not a change.',
  not_successful: 'One side did not complete.',
  target_mismatch: 'The observations are for different targets.',
  check_mismatch: 'Different checks produced them.',
  missing_version: 'A check, scenario or corpus version is missing, so they are not compared.',
  corpus_changed: 'The signature corpus changed between them.',
  scenario_changed: 'The scenario changed between them.',
  check_version_changed: 'The check definition changed between them.',
  context_mismatch: 'They differ in family, origin relation or producer.',
  provider_not_recorded: 'A provider is not recorded on one side, so a provider change cannot be confirmed.',
});

const DIRECTION_LABELS = Object.freeze({
  appeared: 'Appeared',
  disappeared: 'Disappeared',
  improvement: 'Improved (gap to pass)',
  regression: 'Regressed (pass to gap)',
  unclassified: 'Changed',
  provider_changed: 'Provider changed',
});

export function comparisonReasonLabel(reason) {
  return COMPARISON_REASONS[text(reason)] ?? titleCase(text(reason) || 'not_recorded');
}

export function changeDirectionLabel(direction) {
  return DIRECTION_LABELS[text(direction)] ?? 'Changed';
}
