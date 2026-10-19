/**
 * AI insights for the open page or record: which board to ask for, and strict validation of
 * the server board before it renders. Numbers come from the server; nothing here computes them.
 */
import { sanitizeDataResult } from './assistant-visuals.mjs';
import { parseRouteHash } from './assistant-page-context.mjs';

export const INSIGHT_CACHE_TTL_MS = 10 * 60 * 1000;
export const MAX_GROUP_FINDINGS = 100;

const TONES = new Set(['critical', 'caution', 'positive', 'neutral']);
const UNITS = new Set(['count', 'percent', 'score', 'days']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const ID = /^[A-Za-z0-9_.:-]{1,120}$/;
const ACTION_ROUTE = /^[a-z][a-z0-9-]{1,40}(?:\?[a-z_]{1,20}=[A-Za-z0-9_.:%-]{1,200})?$/;

const ROUTE_SCOPES = Object.freeze({
  dashboard: { kind: 'dashboard', label: 'Dashboard' },
  targets: { kind: 'targets', label: 'Targets' },
  'target-detail': { kind: 'target', label: 'Target', param: 'id' },
  checks: { kind: 'check_library', label: 'Check library' },
  'check-detail': { kind: 'check', label: 'Check', param: 'id' },
  'test-policies': { kind: 'schedules', label: 'Validation schedules' },
  'policy-detail': { kind: 'schedule', label: 'Schedule', param: 'id' },
  findings: { kind: 'findings', label: 'Findings' },
  'finding-detail': { kind: 'finding', label: 'Finding', param: 'id' },
  'finding-group-detail': { kind: 'finding_group', label: 'Finding group', param: 'key' },
  runs: { kind: 'runs', label: 'Test runs' },
  'run-detail': { kind: 'run', label: 'Run', param: 'id' },
  audit: { kind: 'audit', label: 'Audit log' },
});

/** @param {unknown} value @param {number} max */
function text(value, max) {
  if (value === null || value === undefined) return '';
  const raw = typeof value === 'string' || typeof value === 'number' ? String(value) : '';
  return raw.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/**
 * The insight scope for a route. Record pages need their id; a finding group also needs its
 * member finding ids, which only the page knows, so it is published by the page.
 */
export function insightScopeForRoute(route, params = {}, override = null) {
  if (override && override.route === route && override.kind) return sanitizeScope(override);
  const meta = ROUTE_SCOPES[route];
  if (!meta) return { route, kind: 'workspace', label: 'Workspace' };
  if (!meta.param) return { route, kind: meta.kind, label: meta.label };
  const id = text(params?.[meta.param], 120);
  if (!ID.test(id) || meta.kind === 'finding_group') return null;
  return { route, kind: meta.kind, label: meta.label, entity: { id } };
}

/** Caps and validates a scope; anything malformed is rejected rather than repaired. */
export function sanitizeScope(value) {
  if (!value || typeof value !== 'object') return null;
  const kind = text(value.kind, 40).replace(/[^a-z_]/g, '');
  if (!kind) return null;
  const out = { route: text(value.route, 60).replace(/[^a-z0-9-]/gi, ''), kind, label: text(value.label, 80) || 'Page' };
  const subject = text(value.subject, 120);
  if (subject) out.subject = subject;
  const id = text(value.entity?.id, 120);
  if (id) {
    if (!ID.test(id)) return null;
    out.entity = { id };
  }
  if (Array.isArray(value.finding_ids)) {
    const ids = [...new Set(value.finding_ids.map((item) => text(item, 120)).filter((item) => ID.test(item)))].slice(0, MAX_GROUP_FINDINGS);
    if (!ids.length) return null;
    out.finding_ids = ids;
  }
  return out;
}

/** Scope for whatever page is open right now. */
export function currentInsightScope(hash, override = null) {
  const { route, params } = parseRouteHash(hash);
  return insightScopeForRoute(route, params, override);
}

export function insightRequestBody(scope, { narrative = true, refresh = false } = {}) {
  return {
    kind: scope.kind,
    ...(scope.entity ? { entity: { id: scope.entity.id } } : {}),
    ...(scope.finding_ids ? { finding_ids: scope.finding_ids } : {}),
    narrative,
    ...(refresh ? { refresh: true } : {}),
  };
}

export function insightCacheKey(identity, scope) {
  return [identity, scope.kind, scope.entity?.id ?? '', (scope.finding_ids ?? []).join(',')].join('|');
}

function sanitizeKpi(value) {
  if (!value || typeof value !== 'object') return null;
  const label = text(value.label, 60);
  if (!label) return null;
  const number = typeof value.value === 'number' && Number.isFinite(value.value) ? value.value : null;
  return {
    id: text(value.id, 40) || label,
    label,
    value: number,
    unit: UNITS.has(value.unit) ? value.unit : 'count',
    tone: TONES.has(value.tone) ? value.tone : 'neutral',
    ...(text(value.detail, 160) ? { detail: text(value.detail, 160) } : {}),
  };
}

function sanitizeAction(value) {
  if (!value || typeof value !== 'object') return null;
  const title = text(value.title, 140);
  if (!title) return null;
  const route = text(value.route, 240);
  return {
    severity: SEVERITIES.has(value.severity) ? value.severity : 'info',
    title,
    ...(text(value.detail, 240) ? { detail: text(value.detail, 240) } : {}),
    ...(ACTION_ROUTE.test(route) ? { route } : {}),
  };
}

export function sanitizeNarrative(value) {
  if (!value || typeof value !== 'object') return null;
  const summary = text(value.summary, 700);
  if (!summary) return null;
  const takeaways = (Array.isArray(value.takeaways) ? value.takeaways : []).map((item) => text(item, 260)).filter(Boolean).slice(0, 4);
  return { summary, takeaways, ai: value.ai === true };
}

/** Validates the server board; returns null when it is not usable. */
export function sanitizeBoard(value) {
  if (!value || typeof value !== 'object') return null;
  const verdict = value.verdict && typeof value.verdict === 'object' ? value.verdict : null;
  const headline = text(verdict?.headline, 300);
  if (!headline) return null;
  const score = typeof verdict.score === 'number' && Number.isFinite(verdict.score) ? Math.max(0, Math.min(100, Math.round(verdict.score))) : null;
  const sections = (Array.isArray(value.sections) ? value.sections : []).slice(0, 6).flatMap((section) => {
    const result = sanitizeDataResult(section);
    if (!result || !result.rows.length) return [];
    const hint = text(section.hint, 200);
    return [{ ...result, ...(hint ? { hint } : {}) }];
  });
  const scope = value.scope && typeof value.scope === 'object' ? value.scope : {};
  return {
    kind: text(value.kind, 40),
    ...(text(value.subject, 120) ? { subject: text(value.subject, 120) } : {}),
    generated_at: text(value.generated_at, 40),
    verdict: { tone: TONES.has(verdict.tone) ? verdict.tone : 'neutral', score, headline },
    kpis: (Array.isArray(value.kpis) ? value.kpis : []).map(sanitizeKpi).filter(Boolean).slice(0, 5),
    sections,
    actions: (Array.isArray(value.actions) ? value.actions : []).map(sanitizeAction).filter(Boolean).slice(0, 5),
    narrative: sanitizeNarrative(value.narrative) ?? { summary: headline, takeaways: [], ai: false },
    truncated: scope.truncated === true,
    noAccess: scope.no_access === true,
  };
}

export function sanitizeNarrativeState(value) {
  const status = ['queued', 'unavailable', 'rate_limited', 'not_requested'].includes(value?.status) ? value.status : 'unavailable';
  const jobId = typeof value?.job_id === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(value.job_id) ? value.job_id : '';
  return { status: status === 'queued' && !jobId ? 'unavailable' : status, jobId, reason: text(value?.reason, 60) };
}

/** Display value for a KPI, without the unit suffix the card adds itself. */
export function formatKpi(kpi) {
  if (kpi.value === null) return '—';
  if (kpi.unit === 'percent') return `${Math.round(kpi.value)}`;
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(kpi.value);
}

export function kpiUnitSuffix(kpi) {
  if (kpi.value === null) return '';
  if (kpi.unit === 'percent') return '%';
  if (kpi.unit === 'score') return '/100';
  if (kpi.unit === 'days') return kpi.value === 1 ? ' day' : ' days';
  return '';
}

export function narrativeUnavailableMessage(state) {
  if (state.status === 'rate_limited') return 'AI summary paused for a minute because of the request limit. The computed summary is shown.';
  if (state.reason === 'assistant_runner_offline') return 'The AI runner is offline, so the computed summary is shown.';
  if (state.status === 'unavailable') return 'An AI summary is not available right now. The computed summary is shown.';
  return '';
}
