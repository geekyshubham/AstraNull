import { isFindingOpen } from './finding-lifecycle.mjs';
import type { DataItem, PortalData } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNumber(item: DataItem | null | undefined, keys: string[]): number | null {
  if (!item) return null;
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return null;
}

export function countActiveTargets(targets: DataItem[]) {
  return targets.filter((target) => !target.archived_at && !target.deleted_at).length;
}

export function countOpenFindings(findings: DataItem[]) {
  return findings.filter(isFindingOpen).length;
}

export function countHighScaleRequests(highScale: DataItem[]) {
  return highScale.length;
}

export type DashboardMetrics = {
  targets: number;
  openFindings: number;
  highScaleRequests: number;
};

/** Prefer `/v1/state` fields; fall back to list APIs with the same semantics as `src/services/state.mjs`. */
export function resolveDashboardMetrics(data: PortalData): DashboardMetrics {
  return {
    targets: data.targets.filter((target) => !target.archived_at && !target.deleted_at).length,
    openFindings: data.state?.open_findings ?? countOpenFindings(data.findings),
    highScaleRequests: data.state?.high_scale_requests ?? countHighScaleRequests(data.highScale)
  };
}

export function resolveRecentRuns(data: PortalData, limit = 5) {
  const fromState = Array.isArray(data.state?.recent_runs) ? data.state.recent_runs : null;
  const source = fromState ?? data.runs;
  return [...source].slice(-limit).reverse();
}

/* ---------- Outside-in derivations (targets-first, no agents/environments) ---------- */

const VERIFIED_STATES = new Set(['dns_verified', 'provider_verified', 'user_confirmed', 'verified']);
const PASS_VERDICTS = new Set(['pass', 'passed', 'protected', 'success', 'ok', 'allowed_as_expected']);
const GAP_VERDICTS = new Set(['gap', 'fail', 'failed', 'penetrated', 'bypassable', 'edge_exposed', 'unprotected']);
const PENDING_VERDICTS = new Set(['', 'pending', 'planned', 'running', 'collecting']);

export type EvidenceStatus = 'pass' | 'review' | 'gap' | 'none';

/** Verification state string for a target, tolerant of nested `verification.state` or flat fields. */
export function targetVerificationState(target: DataItem): string {
  const nested = target.verification;
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    const state = getString(nested as DataItem, ['state']);
    if (state) return state.toLowerCase();
  }
  return getString(target, ['verification_state'], 'unverified').toLowerCase();
}

export function isTargetVerified(target: DataItem): boolean {
  return VERIFIED_STATES.has(targetVerificationState(target));
}

/** Free-form tags declared on a target (ADR-0008 top-level `tags: string[]`), deduped and lowercased. */
export function targetTags(target: DataItem): string[] {
  const raw = target.tags;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    const tag = String(entry ?? '').trim().toLowerCase();
    if (tag && !out.includes(tag)) out.push(tag);
  }
  return out;
}

function runVerdictString(run: DataItem): string {
  const raw = run.verdict;
  if (typeof raw === 'string') return raw.trim().toLowerCase();
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return getString(raw as DataItem, ['verdict', 'status', 'result']).trim().toLowerCase();
  }
  return getString(run, ['verdict']).trim().toLowerCase();
}

export function classifyVerdict(verdict: string): EvidenceStatus {
  const key = verdict.trim().toLowerCase();
  if (PENDING_VERDICTS.has(key)) return 'none';
  if (PASS_VERDICTS.has(key)) return 'pass';
  if (GAP_VERDICTS.has(key)) return 'gap';
  return 'review';
}

function runTimestamp(run: DataItem): string {
  return String(run.completed_at ?? run.started_at ?? run.created_at ?? run.updated_at ?? '');
}

/**
 * A run result counts only when it names its recorded verdict or evidence. A completed status or a
 * bare verdict string on the run row is not a recorded verdict.
 */
export function evidenceBacked(run: DataItem): boolean {
  const verdict = runVerdictString(run);
  if (PENDING_VERDICTS.has(verdict)) return false;
  const nested = run.verdict && typeof run.verdict === 'object' && !Array.isArray(run.verdict) ? (run.verdict as DataItem) : null;
  if (nested && getString(nested, ['id']) !== '') return true;
  if (getString(run, ['verdict_id']) !== '') return true;
  const count = getNumber(run, ['evidence_count']);
  const ids = Array.isArray(run.evidence_ids) ? run.evidence_ids : Array.isArray(nested?.evidence_ids) ? (nested!.evidence_ids as unknown[]) : [];
  return (count !== null && count > 0) || ids.length > 0 || getString(run, ['evidence_id']) !== '';
}

function runFinished(run: DataItem): boolean {
  return ['completed', 'verdicted', 'finalized'].includes(getString(run, ['status']).toLowerCase());
}

export type TargetPostureRow = {
  id: string;
  value: string;
  kind: string;
  groupId: string;
  groupName: string;
  tags: string[];
  verified: boolean;
  verificationState: string;
  verdict: string;
  verdictStatus: EvidenceStatus;
  /** `latest`: newest finished run is backed. `earlier`: a newer finished run has no recorded verdict, so an earlier backed one is shown. `unbacked`: only unbacked finished runs. */
  verdictBasis: 'latest' | 'earlier' | 'unbacked' | 'none';
  verdictRunId: string;
  /** Open findings recorded against this exact target. */
  openFindings: number;
  lastValidatedAt: string;
};

/**
 * One row per declared target with its latest evidence-backed verdict.
 * Runs are matched by `target_id` only: a target never inherits a sibling's or its
 * target group's run (DASH-01/DASH-02). An un-probed target reports "No result" so the
 * dashboard cannot imply a never-tested target was validated (external-evidence-only).
 */
export function buildTargetPostureRows(
  data: PortalData,
  limit?: number,
  options: {
    /** Open findings to count per target; defaults to the loaded page. */
    openFindings?: DataItem[];
    /** Exact server open counts per target id; win over `openFindings` for those targets. */
    openCounts?: ReadonlyMap<string, number>;
  } = {}
): TargetPostureRow[] {
  const latestByTarget = new Map<string, DataItem>();
  const newestFinishedByTarget = new Map<string, DataItem>();
  for (const run of data.runs) {
    const targetId = getString(run, ['target_id']);
    if (!targetId) continue;
    const stamp = runTimestamp(run);
    if (runFinished(run) || evidenceBacked(run)) {
      const newest = newestFinishedByTarget.get(targetId);
      if (!newest || stamp.localeCompare(runTimestamp(newest)) >= 0) newestFinishedByTarget.set(targetId, run);
    }
    if (!evidenceBacked(run)) continue;
    const prev = latestByTarget.get(targetId);
    if (!prev || stamp.localeCompare(runTimestamp(prev)) >= 0) latestByTarget.set(targetId, run);
  }

  const openFindingsByTarget = new Map<string, number>();
  for (const finding of options.openFindings ?? data.findings) {
    const targetId = getString(finding, ['target_id']);
    if (!targetId || !isFindingOpen(finding)) continue;
    openFindingsByTarget.set(targetId, (openFindingsByTarget.get(targetId) ?? 0) + 1);
  }
  options.openCounts?.forEach((count, targetId) => openFindingsByTarget.set(targetId, count));

  const rows = data.targets.map((target) => {
    const id = getString(target, ['id', 'target_id']);
    const openFindings = openFindingsByTarget.get(id) ?? 0;
    const groupId = getString(target, ['target_group_id']);
    const run = latestByTarget.get(id) ?? null;
    const newest = newestFinishedByTarget.get(id) ?? null;
    const verdict = run ? runVerdictString(run) : '';
    const verdictBasis: TargetPostureRow['verdictBasis'] = run
      ? (newest && newest !== run && !evidenceBacked(newest) ? 'earlier' : 'latest')
      : newest ? 'unbacked' : 'none';
    return {
      id,
      value: getString(target, ['value', 'hostname', 'name'], 'Unnamed target'),
      kind: getString(target, ['kind'], 'fqdn').toLowerCase(),
      groupId,
      groupName: getString(target, ['target_group_name', 'target_group_id'], ''),
      tags: targetTags(target),
      verified: isTargetVerified(target),
      verificationState: targetVerificationState(target),
      verdict,
      verdictBasis,
      verdictRunId: run ? getString(run, ['id']) : '',
      // A passing run does not settle a target that still has open findings.
      verdictStatus: classifyVerdict(verdict) === 'pass' && openFindings > 0 ? 'review' : classifyVerdict(verdict),
      openFindings,
      lastValidatedAt: getString(target, ['last_validated_at', 'last_validation_at'])
    } satisfies TargetPostureRow;
  });

  // Worst posture first (gaps), then review, then unproven, then pass (the fixes-first ordering).
  const order: Record<EvidenceStatus, number> = { gap: 0, review: 1, none: 2, pass: 3 };
  rows.sort((left, right) => {
    if (order[left.verdictStatus] !== order[right.verdictStatus]) return order[left.verdictStatus] - order[right.verdictStatus];
    return left.value.localeCompare(right.value);
  });
  return typeof limit === 'number' ? rows.slice(0, limit) : rows;
}

const STAGE_HEADLINE: Record<EvidenceStatus, string> = {
  pass: 'Origin not reachable directly',
  gap: 'Origin reachable directly',
  review: 'Needs review',
  none: 'Not tested live'
};

/** Worst measured stage wins; unmeasured stages never make the path look safer. */
export function overallDefenseStatus(stages: DefensePathStage[]): EvidenceStatus {
  const measured = stages.filter((stage) => !stage.unavailable && stage.status !== 'none');
  if (measured.length === 0) return 'none';
  if (measured.some((stage) => stage.status === 'gap')) return 'gap';
  if (measured.some((stage) => stage.status === 'review') || measured.length < stages.length) return 'review';
  return 'pass';
}

export type DefensePathStage = {
  key: 'internet' | 'edge' | 'waf' | 'origin';
  label: string;
  status: EvidenceStatus;
  headline: string;
  detail: string;
  /** True when the underlying dataset failed to load, so the stage reads "unavailable" not "not measured". */
  unavailable: boolean;
};

/**
 * The four outside-in stages traffic crosses: Internet → Edge/CDN → WAF → Origin.
 * Each stage's status comes only from loaded data; missing evidence is `none`
 * ("not measured"), a load failure is `unavailable`. No value is invented.
 */
export function buildDefensePath(data: PortalData): DefensePathStage[] {
  const targets = data.targets;
  const verifiedCount = targets.filter(isTargetVerified).length;
  const targetsUnavailable = Boolean(data.loadErrors.targets);
  const internet: DefensePathStage = {
    key: 'internet',
    label: 'Internet',
    status: targetsUnavailable ? 'none' : targets.length === 0 ? 'none' : verifiedCount === targets.length ? 'pass' : verifiedCount > 0 ? 'review' : 'gap',
    headline: targetsUnavailable ? 'Data unavailable' : `${verifiedCount}/${targets.length} verified`,
    detail: 'Declared targets with proven ownership are the entry point every probe uses.',
    unavailable: targetsUnavailable
  };

  const waf = data.wafCoverageSummary;
  const wafUnavailable = Boolean(data.loadErrors.wafCoverageSummary);
  const wafProtected = getNumber(waf, ['protected']);
  const wafEdge = getNumber(waf, ['edge_protected']);
  const wafUnder = getNumber(waf, ['underprotected']);
  const wafCoveragePct = getNumber(waf, ['coverage_pct']);
  const byVendor = waf?.by_vendor;
  const vendors = byVendor && typeof byVendor === 'object' && !Array.isArray(byVendor)
    ? Object.keys(byVendor as Record<string, unknown>).filter((name) => name && name.toLowerCase() !== 'generic')
    : [];

  const edge: DefensePathStage = {
    key: 'edge',
    label: 'Edge / CDN',
    status: wafUnavailable ? 'none' : vendors.length > 0 ? 'review' : 'none',
    headline: wafUnavailable ? 'Data unavailable' : vendors.length > 0 ? `${vendors.length} provider${vendors.length === 1 ? '' : 's'} reported` : 'No provider metadata',
    detail: 'Reported edge/CDN providers are declaration context, not proof traffic was blocked.',
    unavailable: wafUnavailable
  };

  let wafStatus: EvidenceStatus = 'none';
  let wafHeadline = 'Not measured';
  if (wafUnavailable) {
    wafHeadline = 'Data unavailable';
  } else if (wafProtected !== null && wafProtected > 0) {
    wafStatus = wafUnder && wafUnder > 0 ? 'review' : 'pass';
    wafHeadline = `${wafProtected} fully validated`;
  } else if (wafEdge !== null && wafEdge > 0) {
    wafStatus = 'review';
    wafHeadline = `${wafEdge} blocked at edge only`;
  } else if (wafUnder !== null && wafUnder > 0) {
    wafStatus = 'gap';
    wafHeadline = 'Protection needs work';
  } else if (waf) {
    wafStatus = 'review';
    wafHeadline = 'Not enough evidence';
  }
  const wafStage: DefensePathStage = {
    key: 'waf',
    label: 'WAF',
    status: wafStatus,
    headline: wafHeadline,
    detail: wafCoveragePct === null ? 'Fully validated share not reported.' : `${Math.round(wafCoveragePct)}% of declared WAF assets fully validated.`,
    unavailable: wafUnavailable
  };

  const runsUnavailable = Boolean(data.loadErrors.runs);
  const originRun = [...data.runs]
    .filter(evidenceBacked)
    .filter((run) => {
      const checkId = getString(run, ['check_id']).toLowerCase();
      const check = data.checks.find((item) => getString(item, ['check_id', 'id']) === getString(run, ['check_id']));
      return checkId.includes('origin') || getString(check ?? {}, ['vector_family']).toLowerCase() === 'origin';
    })
    .sort((left, right) => runTimestamp(right).localeCompare(runTimestamp(left)))[0] ?? null;
  const originVerdict = originRun ? runVerdictString(originRun) : '';
  // An open origin-family finding outranks an older passing run: the gap is still unresolved.
  const openOriginFindings = data.loadErrors.findings ? 0 : data.findings.filter((finding) => {
    if (!isFindingOpen(finding)) return false;
    const checkId = getString(finding, ['check_id']).toLowerCase();
    const title = getString(finding, ['title']).toLowerCase();
    return checkId.startsWith('origin.') || title.includes('origin');
  }).length;
  const originStatus: EvidenceStatus = runsUnavailable
    ? 'none'
    : openOriginFindings > 0 ? 'gap' : classifyVerdict(originVerdict);
  const origin: DefensePathStage = {
    key: 'origin',
    label: 'Origin',
    status: originStatus,
    headline: runsUnavailable
      ? 'Data unavailable'
      : openOriginFindings > 0
        ? `${openOriginFindings} open origin ${openOriginFindings === 1 ? 'finding' : 'findings'}`
        : originRun ? STAGE_HEADLINE[classifyVerdict(originVerdict)] : 'Not tested live',
    detail: openOriginFindings > 0
      ? 'Direct-origin traffic was reachable in recorded evidence and the finding is still open.'
      : originRun ? 'Latest evidence-backed direct-origin check.' : 'Run a bounded direct-origin check before drawing a conclusion.',
    unavailable: runsUnavailable
  };

  return [internet, edge, wafStage, origin];
}

/** Open findings bucketed into critical (S1), high (S2), and other (S3/S4). */
export function findingSeverityBuckets(findings: DataItem[]): { critical: number; high: number; other: number; total: number } {
  let critical = 0;
  let high = 0;
  let other = 0;
  for (const finding of findings) {
    if (!isFindingOpen(finding)) continue;
    const severity = getString(finding, ['severity']).toLowerCase();
    if (['s1', 'critical'].includes(severity)) critical += 1;
    else if (['s2', 'high'].includes(severity)) high += 1;
    else other += 1;
  }
  return { critical, high, other, total: critical + high + other };
}

export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'unrecorded';

export type SeveritySlice = {
  key: SeverityKey;
  label: string;
  count: number;
  /** Whole-number share of all open findings; 0 when nothing is open. */
  share: number;
};

const SEVERITY_SLICE_LABEL: Record<SeverityKey, string> = {
  critical: 'Critical (S1)',
  high: 'High (S2)',
  medium: 'Medium (S3)',
  low: 'Low or info (S4)',
  unrecorded: 'Severity not recorded'
};

/** Normalises a raw finding severity (s1..s4 or word form) to one display bucket. */
export function severityKey(raw: string): SeverityKey {
  const key = raw.trim().toLowerCase();
  if (['s1', 'critical'].includes(key)) return 'critical';
  if (['s2', 'high'].includes(key)) return 'high';
  if (['s3', 'medium', 'moderate'].includes(key)) return 'medium';
  if (['s4', 'low', 'info'].includes(key)) return 'low';
  return 'unrecorded';
}

/**
 * Open findings split by recorded severity, most severe first. Counts come only
 * from loaded findings; a finding without a recognised severity is reported as
 * "not recorded" instead of being folded into a lower bucket.
 */
export function findingSeverityDistribution(findings: DataItem[]): { slices: SeveritySlice[]; total: number } {
  const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, unrecorded: 0 };
  for (const finding of findings) {
    if (!isFindingOpen(finding)) continue;
    counts[severityKey(getString(finding, ['severity']))] += 1;
  }
  const total = counts.critical + counts.high + counts.medium + counts.low + counts.unrecorded;
  const order: SeverityKey[] = ['critical', 'high', 'medium', 'low', 'unrecorded'];
  return {
    total,
    slices: order.map((key) => ({
      key,
      label: SEVERITY_SLICE_LABEL[key],
      count: counts[key],
      share: total > 0 ? Math.round((counts[key] / total) * 100) : 0
    }))
  };
}

const SEVERITY_SHORT_LABEL: Record<SeverityKey, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unrecorded: 'Not recorded'
};

/** One-word severity for compact rows; keeps "S1"-style codes out of dense lists. */
export function severityShortLabel(raw: string): string {
  return SEVERITY_SHORT_LABEL[severityKey(raw)];
}

/** The same split from exact server counts per bucket (for example `status=open&severity=...` totals). */
export function severityDistributionFromCounts(counts: Record<SeverityKey, number>): { slices: SeveritySlice[]; total: number } {
  const order: SeverityKey[] = ['critical', 'high', 'medium', 'low', 'unrecorded'];
  const total = order.reduce((sum, key) => sum + (counts[key] ?? 0), 0);
  return {
    total,
    slices: order.map((key) => ({
      key,
      label: SEVERITY_SLICE_LABEL[key],
      count: counts[key] ?? 0,
      share: total > 0 ? Math.round(((counts[key] ?? 0) / total) * 100) : 0
    }))
  };
}
