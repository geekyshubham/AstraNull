/**
 * Pure logic for the target ("domain") page: the run-all check set, per-check status rows,
 * WAF/CDN edge-evidence signals, and WAF/CDN efficacy derived from check verdicts.
 *
 * Evidence over assertion: a check only counts toward efficacy when it produced a definitive
 * external-probe verdict. Transport-only (E2) checks are shown as observations and never score;
 * declaration-only (E1) checks perform no network I/O and are not part of "run all".
 */
import { checkExclusionReason, checkSupportsTarget } from './check-picker.mjs';
import { MAX_SCAN_CHECKS } from './validation-scan.mjs';

export const EDGE_DETECTION_CHECK_ID = 'waf.fingerprint.safe';
const DECLARATION_ONLY_KIND = 'metadata_marker';

/** Vector family → category. `layer` decides which efficacy (WAF or CDN) a verdict feeds. */
export const CHECK_CATEGORIES = Object.freeze({
  waf: { id: 'waf', label: 'Web application firewall', layer: 'waf', icon: 'shield', how: 'Sends benign attack markers (SQL injection, XSS, traversal, encoding evasions) and checks the edge blocks them before they reach your application.' },
  exploit: { id: 'exploit', label: 'Exploit classes', layer: 'waf', icon: 'bug', how: 'Records declared readiness for known exploit classes. No live traffic is sent.' },
  origin: { id: 'origin', label: 'Origin exposure', layer: 'origin', icon: 'server', how: 'Looks for a path that reaches your origin server directly, which would bypass the WAF and CDN entirely.' },
  l7: { id: 'l7', label: 'HTTP application layer', layer: 'cdn', icon: 'globe', how: 'Bounded HTTP probes for rate limiting, slow requests, cache abuse, and bot challenges at the edge.' },
  protocol: { id: 'protocol', label: 'Protocol machinery', layer: 'cdn', icon: 'workflow', how: 'HTTP/2, HTTP/3 (QUIC), WebSocket, and gRPC handshake posture probes.' },
  tls: { id: 'tls', label: 'TLS', layer: 'cdn', icon: 'lock', how: 'TLS version, cipher, session, and renegotiation posture checks.' },
  l3_l4: { id: 'l3_l4', label: 'Network and transport', layer: 'cdn', icon: 'network', how: 'TCP and UDP reachability and firewall exposure checks against the declared target.' },
  dns: { id: 'dns', label: 'DNS', layer: 'cdn', icon: 'dns', how: 'Direct DNS queries for resolver, recursion, DNSSEC, zone transfer, and failover posture.' },
  reflection: { id: 'reflection', label: 'Reflection exposure', layer: 'cdn', icon: 'radio', how: 'Single protocol-correct requests confirm the target is not an open reflector.' },
  amplification: { id: 'amplification', label: 'Amplification exposure', layer: 'cdn', icon: 'waves', how: 'Checks that the target does not answer small requests with large amplified responses.' },
  pattern: { id: 'pattern', label: 'Delivery patterns', layer: 'cdn', icon: 'activity', how: 'Records declared readiness for multi-vector and pulse delivery patterns. No live traffic is sent.' },
  operations: { id: 'operations', label: 'Operational readiness', layer: 'ops', icon: 'bell', how: 'Alerting, runbook, and kill-switch readiness self-checks. No traffic reaches your target.' },
  path: { id: 'path', label: 'Protected path', layer: 'cdn', icon: 'globe', how: 'Sends canary traffic down a declared protected path and confirms it arrives as expected.' },
  high_scale: { id: 'high_scale', label: 'High-scale readiness', layer: 'cdn', icon: 'activity', how: 'SOC-governed high-scale scenarios. Customers request them; only the SOC can run them.' },
});
const OTHER_CATEGORY = Object.freeze({ id: 'other', label: 'Other', layer: 'other', icon: 'shield', how: 'Bounded external check.' });
const CATEGORY_ORDER = ['waf', 'origin', 'l7', 'path', 'protocol', 'tls', 'l3_l4', 'dns', 'reflection', 'amplification', 'operations', 'exploit', 'pattern', 'high_scale'];

const PASS_VERDICTS = new Set(['protected', 'pass', 'passed', 'success', 'ok', 'edge_protected', 'allowed_as_expected']);
const FAIL_VERDICTS = new Set(['edge_exposed', 'exposed', 'unprotected', 'gap', 'fail', 'failed', 'bypassable', 'penetrated']);
const ACTIVE_RUN_STATUSES = new Set(['pending', 'planned', 'queued', 'running', 'collecting']);
const STEP_STATUS = Object.freeze({ pending: 'queued', deferred: 'waiting', starting: 'running', running: 'running', collecting: 'running', denied: 'blocked', skipped: 'skipped', cancelled: 'cancelled' });

export const ROW_STATUS_META = Object.freeze({
  passed: { label: 'Protected', tone: 'success' },
  failed: { label: 'Exposed', tone: 'danger' },
  inconclusive: { label: 'Inconclusive', tone: 'warn' },
  observed: { label: 'Observed', tone: 'muted' },
  running: { label: 'Running', tone: 'info' },
  queued: { label: 'Queued', tone: 'muted' },
  waiting: { label: 'Waiting', tone: 'warn' },
  blocked: { label: 'Not run · safety gate', tone: 'warn' },
  skipped: { label: 'Skipped', tone: 'muted' },
  cancelled: { label: 'Cancelled', tone: 'muted' },
  not_run: { label: 'Not run yet', tone: 'muted' },
});
export const ROW_STATUS_ORDER = ['failed', 'running', 'waiting', 'queued', 'inconclusive', 'blocked', 'passed', 'observed', 'skipped', 'cancelled', 'not_run'];

function text(value) {
  return String(value ?? '').trim();
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
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

/** E1 checks perform no network I/O and always verdict inconclusive, so they are not "run". */
export function isDeclarationOnlyCheck(check) {
  return tierOf(check) === 'E1' || text(check?.probe_profile?.kind) === DECLARATION_ONLY_KIND;
}

function runOrder(check) {
  if (text(check.check_id) === EDGE_DETECTION_CHECK_ID) return 0;
  if (text(check.vector_family) === 'origin') return 1;
  return tierOf(check) === 'E3' ? 2 : 3;
}

/**
 * Customer-runnable, target-compatible, network-observable checks for one target, ordered so the
 * WAF/CDN fingerprint runs first and origin exposure next. Capped at the scan contract limit.
 */
export function runAllChecks(checks, target) {
  const eligible = list(checks).filter((check) => text(check?.check_id)
    && !checkExclusionReason(check)
    && checkSupportsTarget(check, target)
    && !isDeclarationOnlyCheck(check));
  const unique = [...new Map(eligible.map((check) => [text(check.check_id), check])).values()];
  return unique
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

function classifyVerdict(verdict, check) {
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
  let rowStatus = STEP_STATUS[status] ?? 'queued';
  if (status === 'verdicted') rowStatus = verdictText ? classifyVerdict(verdictText, check) : 'inconclusive';
  return {
    status: rowStatus,
    verdict: verdictText,
    explanation: text(verdict?.explanation),
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
  let rowStatus;
  if (ACTIVE_RUN_STATUSES.has(runStatus)) rowStatus = 'running';
  else if (runStatus === 'cancelled') rowStatus = 'cancelled';
  // A verdict without cited evidence is not a result (same rule as the run tables).
  else if (published && verdictEvidenceIds(run).length > 0) rowStatus = classifyVerdict(verdictText, check);
  else rowStatus = tierOf(check) === 'E2' ? 'observed' : 'inconclusive';
  return {
    status: rowStatus,
    verdict: published ? verdictText : '',
    explanation: text(record(run.verdict)?.explanation),
    reason: '',
    eligibleAt: '',
    runId: text(run.id),
    startedAt: runTime(run),
    finishedAt: text(run.completed_at ?? run.verdict_at),
    request: null,
    response: null,
    requestsSent: null,
    requestsSimulated: false,
    source: 'run',
  };
}

function emptyRow() {
  return {
    status: 'not_run', verdict: '', explanation: '', reason: '', eligibleAt: '', runId: '', startedAt: '', finishedAt: '',
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
      name: text(check.name) || checkId,
      description: text(check.description),
      verdictLogic: text(check.verdict_logic),
      tier: tierOf(check),
      probeKind: text(check.probe_profile?.kind),
      maxRequests: Number.isFinite(Number(check.probe_profile?.max_requests)) ? Number(check.probe_profile.max_requests) : null,
      timeoutMs: Number.isFinite(Number(check.probe_profile?.timeout_ms)) ? Number(check.probe_profile.timeout_ms) : null,
      category: categoryForCheck(check),
      label: meta.label,
      tone: meta.tone,
    };
  });
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

const EFFICACY_META = Object.freeze({
  protecting: { label: 'Protecting', tone: 'success' },
  partial: { label: 'Partially protecting', tone: 'warn' },
  not_protecting: { label: 'Not protecting', tone: 'danger' },
  bypassable: { label: 'Bypassable via origin', tone: 'danger' },
  present_unmeasured: { label: 'Detected · not measured yet', tone: 'info' },
  absent: { label: 'Not detected', tone: 'warn' },
  unknown: { label: 'Not evaluated yet', tone: 'muted' },
});

function originExposed(rows, edge) {
  if (list(rows).some((row) => row.category?.layer === 'origin' && row.status === 'failed')) return true;
  return text(record(record(edge?.network_firewall)?.direct_origin_reachability)?.status) === 'exposed';
}

function layerEfficacy(layer, rows, edge, exposed) {
  const family = record(edge?.[layer]);
  const familyStatus = text(family?.status);
  const scored = list(rows).filter((row) => row.category?.layer === layer && ['passed', 'failed'].includes(row.status));
  let passed = scored.filter((row) => row.status === 'passed').length;
  let failed = scored.length - passed;
  let basis = 'checks';
  const effectiveness = record(edge?.effectiveness);
  if (layer === 'waf' && scored.length === 0 && Number(effectiveness?.tested_count) > 0) {
    // Before a full run, the fingerprint scan's own benign marker probes are the only evidence.
    passed = Number(effectiveness.blocked_count) || 0;
    failed = Number(effectiveness.passed_count) || 0;
    basis = 'fingerprint_markers';
  }
  const tested = passed + failed;
  let status;
  if (tested === 0) status = familyStatus === 'detected' ? 'present_unmeasured' : familyStatus === 'not_detected' ? 'absent' : 'unknown';
  else if (failed === 0) status = exposed ? 'bypassable' : 'protecting';
  else if (passed === 0) status = 'not_protecting';
  else status = exposed ? 'bypassable' : 'partial';
  const inconclusive = list(rows).filter((row) => row.category?.layer === layer && row.status === 'inconclusive').length;
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
    score: tested ? Math.round((passed / tested) * 100) : null,
    basis,
    originExposed: exposed,
    exposedChecks: scored.filter((row) => row.status === 'failed').map((row) => row.name),
  };
}

/** WAF and CDN efficacy: does the observed evidence show each layer actually protecting? */
export function assessEdgeEfficacy({ rows = [], edge = null } = {}) {
  const exposed = originExposed(rows, edge);
  return { waf: layerEfficacy('waf', rows, edge, exposed), cdn: layerEfficacy('cdn', rows, edge, exposed), originExposed: exposed };
}

export function efficacySentence(efficacy) {
  const thing = efficacy.layer === 'waf' ? 'attack classes' : 'edge checks';
  const basis = efficacy.basis === 'fingerprint_markers' ? 'fingerprint scan markers' : thing;
  if (efficacy.status === 'unknown') return 'No evidence yet. Run all checks to measure it.';
  if (efficacy.status === 'absent') return `No ${efficacy.layer === 'waf' ? 'WAF' : 'CDN'} was detected in front of this domain, and no check has measured blocking yet.`;
  if (efficacy.status === 'present_unmeasured') return 'Detected in front of this domain, but no check has tested whether it blocks anything. Run all checks to measure it.';
  const ratio = `Blocked ${efficacy.passed} of ${efficacy.tested} tested ${basis}`;
  if (efficacy.status === 'bypassable') return `${ratio}, but your origin is reachable directly, so traffic can go around the edge.`;
  if (efficacy.status === 'protecting') return `${ratio}.`;
  return `${ratio}. ${efficacy.failed} reached your application.`;
}

const SOURCE_COPY = Object.freeze({
  response_header: { method: 'HTTP response header', detail: 'An edge platform header in the HTTP response matched this provider.' },
  response_fingerprint: { method: 'WAF fingerprint', detail: 'Benign probe responses matched this WAF\'s fingerprint (wafw00f plugin).' },
  address_range: { method: 'IP address range', detail: 'A resolved address sits inside this provider\'s published network range.' },
  cname_suffix: { method: 'DNS CNAME', detail: 'The domain\'s CNAME chain points into this provider\'s edge.' },
  corroborated_generic_behavior: { method: 'Block behavior', detail: 'Benign attack markers were blocked with a WAF-style response; the vendor is unknown.' },
  legacy_provider_summary: { method: 'Earlier detection', detail: 'Recorded by an earlier detection run.' },
});

/** Display name for a provider code. */
export function providerName(code, displayName = '') {
  const known = {
    cloudflare: 'Cloudflare', akamai: 'Akamai', cloudfront: 'Amazon CloudFront', amazon: 'Amazon', aws: 'AWS', awswaf: 'AWS WAF',
    azure: 'Microsoft Azure', azure_front_door: 'Azure Front Door', fastly: 'Fastly', gcp: 'Google Cloud', google: 'Google Cloud',
    incapsula: 'Imperva (Incapsula)', imperva: 'Imperva', sucuri: 'Sucuri', stackpath: 'StackPath', vercel: 'Vercel', netlify: 'Netlify',
    bunnycdn: 'Bunny CDN', keycdn: 'KeyCDN', gcore: 'Gcore', cdn77: 'CDN77', modsecurity: 'ModSecurity', generic: 'Unidentified WAF',
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
  const layers = list(presented.layers).map((raw) => {
    const layer = record(raw) ?? {};
    const provider = text(layer.provider);
    const matched = vendorMatches.find((match) => text(record(match)?.vendor) === provider);
    const signals = list(record(matched)?.matched_signals).map((signal) => text(record(signal)?.signal)).filter(Boolean);
    return {
      family: text(layer.family),
      provider,
      name: providerName(provider, layer.display_name),
      logo: providerLogoId(provider),
      confidence: Number.isFinite(Number(layer.confidence)) ? Math.round(Number(layer.confidence) * 100) : null,
      agreement: text(layer.evidence_consistency),
      conflicting: layer.conflicting === true,
      sources: list(layer.sources).map((source) => ({ id: text(source), ...(SOURCE_COPY[text(source)] ?? { method: titleCase(source), detail: '' }) })),
      signals: [...new Set(signals)].slice(0, 6),
    };
  });
  const facts = [];
  const chain = list(evidence.dns_cname_chain ?? presented.dns_cname_chain).map(text).filter(Boolean);
  if (chain.length) facts.push({ id: 'cname', label: 'CNAME chain', value: chain.join(' → ') });
  const ips = list(evidence.dns_resolved_ips ?? presented.dns_resolved_ips).map(text).filter(Boolean);
  if (ips.length) facts.push({ id: 'ips', label: 'Resolved addresses', value: ips.slice(0, 6).join(', ') });
  const wafw00f = record(evidence.wafw00f);
  if (wafw00f) {
    const firewall = text(wafw00f.firewall);
    facts.push({
      id: 'wafw00f',
      label: 'wafw00f',
      value: wafw00f.detected === true && firewall && firewall !== 'None'
        ? `${firewall}${text(wafw00f.manufacturer) && text(wafw00f.manufacturer) !== 'None' ? ` (${text(wafw00f.manufacturer)})` : ''}`
        : record(wafw00f.generic)?.found === true ? 'Generic WAF behavior detected' : 'No WAF plugin matched',
    });
  }
  const cdncheck = record(evidence.cdncheck);
  if (cdncheck) {
    facts.push({
      id: 'cdncheck',
      label: 'cdncheck',
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
  if (record(edge)) return text(edge.status) || 'inconclusive';
  if (localRequest === 'pending' || scanFingerprintActive) return 'evaluating';
  if (ACTIVE_RUN_STATUSES.has(text(record(request)?.run_status).toLowerCase())) return 'evaluating';
  if (!eligible) return 'locked';
  if (localRequest === 'blocked') return 'waiting';
  if (localRequest === 'error') return 'error';
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

export function validationScansPathForTarget(targetGroupId, targetId) {
  const params = new URLSearchParams({ target_group_id: text(targetGroupId), target_id: text(targetId), limit: '1' });
  return `/v1/validation-scans?${params.toString()}`;
}
