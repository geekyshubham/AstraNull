import { effectiveTargetKind } from '../contracts/checkTargetCompatibility.mjs';
import { CHECK_CATALOG } from '../contracts/checks.mjs';
import { coverageFrom, summarizePairs, COVERAGE_FRESHNESS_POLICY } from './protectionCoverage.mjs';
import { REQUIRED_ARTIFACT_TYPES, authorizationPackComplete, distinctSocApprovalCount } from './highScalePolicy.mjs';

export const READINESS_ASSESSMENT_VERSION = 'readiness-assessment.v2';
export const FINDING_SEVERITY_PENALTIES = Object.freeze({ critical: 20, high: 10, medium: 5, low: 1, informational: 0, info: 0, unknown: 5 });
const rows = (value) => Array.isArray(value) ? value : [];
const ts = (value) => { const ms = value == null ? NaN : new Date(value).getTime(); return Number.isFinite(ms) ? ms : null; };
const sameTenant = (row, tenantId) => row?.tenant_id === tenantId;
const plural = (count, noun) => (count === 1 ? noun : `${noun}s`);
function available(row, nowMs, fallback) {
  const times = [row?.created_at, row?.ingested_at].filter((value) => value != null).map(ts);
  if (!times.length) times.push(ts(fallback));
  return times.every((time) => time != null && time <= nowMs);
}

/** Only actual same-run signed results can back a verdict; activity and unlinked vault IDs cannot. */
export function verifiedVerdicts({ tenantId, runs = [], verdicts = [], events = [], evidenceItems = [], nowMs = Date.now() }) {
  const runById = new Map(rows(runs).filter((run) => sameTenant(run, tenantId)).map((run) => [run.id, run]));
  const eventById = new Map(rows(events).filter((event) => {
    const run = runById.get(event.test_run_id);
    const nonce = run?.correlation?.nonce_hash ?? run?.correlation_json?.nonce_hash;
    return sameTenant(event, tenantId) && run && typeof nonce === 'string' && nonce.length > 0
      && event.nonce_hash === nonce && ts(event.ingested_at) != null
      && event.signal_type === 'probe_result' && event.producer_kind === 'signed_probe'
      && available(event, nowMs, event.timestamp) && ts(event.timestamp) != null && ts(event.timestamp) <= nowMs;
  }).map((event) => [event.id, event]));
  const evidenceById = new Map(rows(evidenceItems).filter((item) => {
    const event = eventById.get(item.related_event_id);
    return sameTenant(item, tenantId) && event && item.test_run_id === event.test_run_id && available(item, nowMs, event.timestamp);
  }).map((item) => [item.id, item]));
  const byRun = new Map();
  for (const verdict of rows(verdicts)) {
    if (!sameTenant(verdict, tenantId) || !runById.has(verdict.test_run_id) || !available(verdict, nowMs)) continue;
    const ids = rows(verdict.evidence_ids);
    if (!ids.length) continue;
    const resultEvents = ids.map((id) => eventById.get(id) ?? eventById.get(evidenceById.get(id)?.related_event_id));
    if (resultEvents.some((event) => !event || event.test_run_id !== verdict.test_run_id)) continue;
    const prior = byRun.get(verdict.test_run_id);
    if (prior && (ts(prior.verdict.created_at) > ts(verdict.created_at) || ts(prior.verdict.created_at) === ts(verdict.created_at) && String(prior.verdict.id).localeCompare(String(verdict.id)) > 0)) continue;
    const observationTime = Math.min(...resultEvents.map((event) => ts(event.timestamp)));
    const metadata = resultEvents.map((event) => event.metadata ?? event.metadata_json ?? {});
    const observationOnly = metadata.some((entry) => entry.observation_only === true || entry.readiness_conclusion === false);
    const incomplete = metadata.some((entry) => entry.complete === false || entry.comparison_complete === false || entry.planned_legs_complete === false || entry.evidence_complete === false);
    byRun.set(verdict.test_run_id, { verdict, observed_at: new Date(observationTime).toISOString(), evidence_verified: true, observation_only: observationOnly, incomplete, result_metadata: metadata });
  }
  return byRun;
}

const MAX_GATE_LABEL_LENGTH = 80;

function requestLabel(request) {
  const text = String(request?.objective ?? request?.reason ?? '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  return text.length > MAX_GATE_LABEL_LENGTH ? `${text.slice(0, MAX_GATE_LABEL_LENGTH - 1).trimEnd()}…` : text;
}

function namedRequest(label) {
  return label ? `High-scale request "${label}"` : 'A high-scale request';
}

function pendingGateSummary(pending) {
  if (!pending.length) return '';
  const artifactCount = pending.reduce((sum, gate) => sum + gate.missing_artifacts.length, 0);
  const artifactText = `${artifactCount} missing accepted ${plural(artifactCount, 'artifact')}`;
  if (pending.length === 1) {
    const [gate] = pending;
    const parts = [gate.missing_artifacts.length ? artifactText : gate.pack_complete ? '' : 'authorization artifact validity or scope incomplete', `SOC approvals ${gate.approvals}/2`].filter(Boolean);
    return `Pending gates remain on ${gate.named ? `high-scale request "${gate.label}"` : '1 high-scale request'}: ${parts.join(', ')}.`;
  }
  const awaitingApproval = pending.filter((gate) => gate.approvals < 2).length;
  const incompletePacks = pending.filter((gate) => !gate.pack_complete).length;
  const parts = [artifactCount ? artifactText : '', incompletePacks && !artifactCount ? `${incompletePacks} authorization ${plural(incompletePacks, 'pack')} incomplete` : '', awaitingApproval ? `${awaitingApproval} awaiting SOC approvals (2 required)` : ''].filter(Boolean);
  return `Pending gates remain on ${pending.length} high-scale requests: ${parts.join(', ')}.`;
}

export function governancePosture({ tenantId, requests = [], killSwitch = null, auditEntries = [], nowMs = Date.now() }) {
  const scoped = rows(requests).filter((row) => sameTenant(row, tenantId) && (row.created_at == null || available(row, nowMs)));
  const gates = [];
  const evidence = [];
  const killAt = ts(killSwitch?.updated_at);
  if (killSwitch?.tenant_id === tenantId && killAt != null && killAt <= nowMs || rows(auditEntries).some((entry) => sameTenant(entry, tenantId) && ['soc.kill_switch.activated', 'soc.kill_switch.cleared'].includes(entry.action) && available(entry, nowMs, entry.timestamp))) evidence.push('Kill switch state recorded for tenant.');
  for (const request of scoped) {
    const approvals = distinctSocApprovalCount(request);
    const complete = authorizationPackComplete(request, nowMs);
    const label = requestLabel(request);
    if (complete && approvals >= 2) evidence.push(`${namedRequest(label)}: authorization pack accepted with ${approvals} SOC approvers.`);
    if (['scheduled', 'running', 'stopped', 'closed'].includes(request.state) && rows(request.audit_trail).length) evidence.push(`${namedRequest(label)}: governed lifecycle recorded.`);
    if (!['closed', 'rejected'].includes(request.state)) {
      const missing = [];
      let missingArtifacts = [];
      if (!complete) {
        const accepted = new Set(rows(request.artifacts).filter((a) => a.status === 'accepted').map((a) => a.type));
        missingArtifacts = REQUIRED_ARTIFACT_TYPES.filter((type) => !accepted.has(type));
        missing.push(missingArtifacts.length ? `${missingArtifacts.length} missing accepted ${plural(missingArtifacts.length, 'artifact')}` : 'authorization artifact validity or scope incomplete');
      }
      if (approvals < 2) missing.push(`SOC approvals ${approvals}/2`);
      if (missing.length) gates.push({ requestId: request.id, state: request.state, label: label || 'High-scale request', named: Boolean(label), pack_complete: complete, missing, missing_artifacts: missingArtifacts, approvals });
    }
  }
  const pending = gates.map(({ named: _named, ...gate }) => gate);
  const summary = pendingGateSummary(gates);
  return { status: evidence.length ? 'recorded' : 'not_recorded', protection_credit: 0, detail: `${evidence.join(' ') || 'No high-scale governance evidence recorded yet.'}${summary ? ` ${summary}` : ''}`, pending_gates: pending };
}

function active(row) {
  return !row?.archived_at && !row?.deleted_at && !['archived', 'deleted'].includes(row?.status ?? row?.state);
}

/** Versioned current assessment; score is never a capacity, inventory, or all-path protection claim. */
export function projectReadiness(input = {}) {
  const tenantId = input.tenantId;
  const nowMs = ts(input.asOf ?? input.now) ?? Date.now();
  const groups = rows(input.groups).filter((group) => sameTenant(group, tenantId) && active(group));
  const groupById = new Map(groups.map((group) => [group.id, group]));
  const targets = rows(input.targets).filter((target) => sameTenant(target, tenantId) && active(target) && (target.created_at == null || available(target, nowMs)) && (!target.target_group_id || groupById.has(target.target_group_id)));
  const runs = rows(input.runs).filter((run) => sameTenant(run, tenantId) && available(run, nowMs, run.started_at ?? run.completed_at));
  const byRun = verifiedVerdicts({ ...input, runs, nowMs });
  const policies = rows(input.policies).filter((policy) => sameTenant(policy, tenantId));
  // Exact grouping avoids constructing one million identical not-run rows. Applicability
  // is catalog + effective target kind; scopes and policies are still evaluated per
  // target whenever an observation exists. This cache lives only in this projection.
  const observationsByTarget = new Map();
  for (const run of runs) {
    const proof = byRun.get(run.id);
    const projectedRun = proof ? { ...run, readiness_result_metadata: proof.result_metadata,
      ...(proof.observation_only || proof.incomplete ? { probe_metadata: { ...(run.probe_metadata ?? {}),
        observation_only: proof.observation_only, comparison_complete: !proof.incomplete } } : {}) } : run;
    const observation = { check_id: run.check_id, run: projectedRun, verdict: proof?.verdict ?? null,
      evidence_verified: Boolean(proof), observed_at: proof?.observed_at, require_recorded_scope: true };
    const existing = observationsByTarget.get(run.target_id) ?? [];
    existing.push(observation);
    observationsByTarget.set(run.target_id, existing);
  }
  const pairs = [], weightByPair = new Map(), blankTargetsByKind = new Map();
  for (const target of targets) {
    const observations = observationsByTarget.get(target.id);
    if (!observations?.length) {
      const kind = effectiveTargetKind(target);
      const blank = blankTargetsByKind.get(kind) ?? { target, count: 0 };
      blank.count += 1;
      blankTargetsByKind.set(kind, blank);
      continue;
    }
    pairs.push(...coverageFrom({ target, targetGroup: groupById.get(target.target_group_id) ?? null,
      policies, observations, catalog: input.catalog ?? CHECK_CATALOG, nowMs }).coverage.pairs);
  }
  for (const { target, count } of blankTargetsByKind.values()) {
    const template = coverageFrom({ target, observations: [], catalog: input.catalog ?? CHECK_CATALOG, nowMs }).coverage.pairs;
    for (const pair of template) { pairs.push(pair); weightByPair.set(pair, count); }
  }
  const weightOf = (pair) => weightByPair.get(pair) ?? 1;
  const coverage = summarizePairs(pairs, weightOf);
  const passed = coverage.passed_count;
  const findingCounts = rows(input.findingCounts);
  const hasGroupedCounts = input.findingCounts !== undefined || input.finding_counts_complete === true;
  const completeCounts = !hasGroupedCounts || input.finding_counts_complete === true && Array.isArray(input.findingCounts)
    && findingCounts.every((row) => Number.isSafeInteger(row.count) && row.count >= 0 && ts(row.created_at) != null && ts(row.created_at) <= nowMs);
  const complete = input.input_complete === true && completeCounts;
  const activeTargetIds = new Set(targets.map((target) => target.id));
  const qualifiedFinding = (finding) => sameTenant(finding, tenantId) && ['open', 'in_progress', 'accepted_risk'].includes(finding.status ?? finding.state) && (!finding.target_id || activeTargetIds.has(finding.target_id)) && (finding.created_at == null || available(finding, nowMs));
  const findings = hasGroupedCounts ? [] : rows(input.findings).filter(qualifiedFinding);
  const counts = completeCounts ? findingCounts.filter(qualifiedFinding) : [];
  const severityCounts = {};
  let severityPenalty = 0, unresolvedCount = 0;
  for (const finding of [...findings.map((finding) => ({ finding, count: 1 })), ...counts.map((finding) => ({ finding, count: finding.count }))]) {
    const count = finding.count;
    const row = finding.finding;
    unresolvedCount += count;
    const severity = String(row.severity ?? 'unknown').toLowerCase();
    severityCounts[severity] = (severityCounts[severity] ?? 0) + count;
    severityPenalty += count * (FINDING_SEVERITY_PENALTIES[severity] ?? FINDING_SEVERITY_PENALTIES.unknown);
  }
  const maximum = coverage.applicable_count ? Math.floor(100 * passed / coverage.applicable_count) : 0;
  const penalty = Math.min(maximum, severityPenalty);
  const governance = governancePosture({ tenantId, requests: input.highScaleRequests, killSwitch: input.killSwitch, auditEntries: input.auditEntries, nowMs });
  const retestPairs = pairs.filter((pair) => pair.retest_required);
  const score = complete ? Math.max(0, maximum - penalty) : null;
  const legacy = input.legacy_snapshot;
  return {
    assessment_version: READINESS_ASSESSMENT_VERSION,
    score, score_status: !complete ? 'incomplete_inputs' : coverage.applicable_count ? 'current' : 'not_applicable', input_complete: complete,
    confidence: 'external_only', assessment_scope: 'current_compatible_tested_target_check_scenarios',
    factors: [
      { key: 'coverage', label: 'Tested scenario assurance', weight: 100, score: complete ? maximum : null, detail: `${passed} passing of ${coverage.applicable_count} applicable target/check scenarios; ${coverage.not_run_count} not run, ${coverage.inconclusive_count} inconclusive, ${coverage.stale_count} stale. Shared mechanisms are not independent defenses.` },
      { key: 'verdicts', label: 'Severity-aware unresolved findings', weight: 0, score: complete ? (penalty ? -penalty : 0) : null, detail: `${unresolvedCount} unresolved ${plural(unresolvedCount, 'finding')}; severity penalty ${severityPenalty}. Absence of findings is not proof of protection.` },
      { key: 'evidence_freshness', label: 'Immutable evidence freshness', weight: 0, score: 0, detail: `${COVERAGE_FRESHNESS_POLICY.max_age_ms / 86400000}-day observation expiry; ${coverage.stale_count} stale ${plural(coverage.stale_count, 'pair')}. Metadata refresh never renews evidence.` },
      { key: 'soc_readiness', label: 'SOC governance (separate)', weight: 0, score: 0, detail: governance.detail },
    ],
    posture: { pass: passed, gap: coverage.gap_count, not_run: coverage.not_run_count, review: coverage.applicable_count - passed - coverage.gap_count - coverage.not_run_count, total: coverage.applicable_count },
    coverage: { ...coverage, observation_only_count: pairs.reduce((count, pair) => count + (pair.exclusion_reason === 'observation_only' ? weightOf(pair) : 0), 0), unit: 'target_check_pair', target_count: targets.length, observed_target_count: new Set(pairs.filter((pair) => pair.state === 'conclusive').map((pair) => pair.target_id)).size, shared_mechanism_count: new Set(pairs.filter((pair) => pair.state !== 'excluded').map((pair) => pair.mechanism)).size, mechanism_coverage_claim: 'reused_profiles_not_independent_defenses', freshness_policy: COVERAGE_FRESHNESS_POLICY },
    findings: { unresolved_count: unresolvedCount, severity_counts: severityCounts, severity_penalty: severityPenalty },
    governance,
    current_assurance: { status: !complete ? 'incomplete_inputs' : retestPairs.length ? 'retest_required' : passed ? 'tested_scenarios_only' : 'not_established', retest_required_count: retestPairs.length, reasons: [...new Set(retestPairs.map((pair) => pair.pair_reason))].sort() },
    ...(legacy && legacy.assessment_version !== READINESS_ASSESSMENT_VERSION ? { legacy_snapshot: { label: 'legacy_unversioned', authoritative: false, snapshot: legacy } } : {}),
    updated_at: new Date(nowMs).toISOString(),
  };
}
