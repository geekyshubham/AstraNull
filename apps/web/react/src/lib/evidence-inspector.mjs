/**
 * Shared evidence-inspector contract: ID-only hash state, the exact GET /v1/evidence-context
 * query, a pure view model, and late-response guards.
 *
 * Inspection is read-only. Nothing here starts traffic, exports, verifies custody, or sends a
 * message. Refs are navigation hints; the server re-authorizes every read.
 */

export const EVIDENCE_INSPECTOR_EVENT = 'astranull:evidence-inspector';

export const INSPECTOR_ENTRIES = Object.freeze(['finding', 'group_member', 'check_result', 'provider', 'artifact', 'report', 'audit']);
export const PROVIDER_FAMILIES = Object.freeze(['waf', 'cdn', 'cloud', 'dns', 'origin_hosting']);

/** Matches the server's exact-ID rule for GET /v1/evidence-context. */
const SAFE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** Ref field → hash parameter. Only these keys are ever written or read. */
const FIELD_PARAMS = Object.freeze({
  finding_id: 'ev_finding',
  target_id: 'ev_target',
  check_id: 'ev_check',
  test_run_id: 'ev_run',
  family: 'ev_family',
  evidence_id: 'ev_evidence',
  report_id: 'ev_report',
  audit_id: 'ev_audit',
});
const ENTRY_PARAM = 'inspect';
const INSPECTOR_PARAMS = new Set([ENTRY_PARAM, ...Object.values(FIELD_PARAMS)]);

const REQUIRED_FIELDS = Object.freeze({
  finding: ['finding_id'],
  group_member: ['finding_id'],
  check_result: ['target_id', 'check_id', 'test_run_id'],
  provider: ['target_id', 'family'],
  artifact: ['evidence_id'],
  report: ['report_id'],
  audit: ['audit_id'],
});

/** Optional context a ref may carry for its entry; anything else is dropped. */
const ALLOWED_FIELDS = Object.freeze({
  finding: ['finding_id', 'target_id', 'check_id'],
  group_member: ['finding_id', 'target_id', 'check_id'],
  check_result: ['target_id', 'check_id', 'test_run_id'],
  provider: ['target_id', 'family'],
  artifact: ['evidence_id', 'finding_id', 'test_run_id'],
  report: ['report_id'],
  audit: ['audit_id'],
});

/**
 * Route parameters a portal page actually reads. Anything else in the address (unknown keys,
 * invitation or auth codes, pasted payloads) is dropped when the inspector rewrites the hash.
 */
const ROUTE_PARAM_RULES = Object.freeze({
  id: 'id',
  entity_id: 'id',
  tenant: 'id',
  tab: 'slug',
  check: 'id',
  policy: 'id',
  target: 'id',
  key: 'group_key',
  focus: 'slug',
  retest: 'slug',
  variant: 'slug',
  view: 'slug',
  status: 'slug',
  severity: 'slug',
  owner: 'label',
  group: 'id',
  kind: 'slug',
  tag: 'label',
  verification: 'slug',
  sort: 'slug',
  page: 'int',
  q: 'search',
  service_role: 'slug',
  criticality: 'slug',
  owner_status: 'slug',
  family: 'slug',
  family_status: 'slug',
  freshness: 'slug',
  origin_status: 'slug',
  has_open_finding: 'slug',
  unit: 'slug',
  event: 'id',
  target_group_id: 'id',
  target_group: 'id',
  verification_state: 'slug',
  role: 'slug',
  search: 'search',
  actor: 'id',
  category: 'slug',
  resource: 'label',
  from: 'date',
  to: 'date',
  obs: 'id',
  hist_family: 'slug',
  binding: 'id',
});

const CREDENTIAL_NAME = /(token|password|passwd|secret|credential|invite|invitation|auth|session|cookie|bearer|api[_-]?key|signature|code)/i;

/**
 * True for values that look like credentials rather than identifiers: JWTs, bearer strings,
 * provider-prefixed keys, invitation/reset codes and long unbroken high-entropy runs.
 */
export function looksLikeCredential(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return false;
  if (/^bearer\s/i.test(raw)) return true;
  if (/^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/.test(raw)) return true;
  if (/^(sk|pk|rk)_(live|test)_/i.test(raw)) return true;
  if (/^(gh[pousr]_|xox[abprs]-|AKIA[0-9A-Z]{12}|pwi_|pwr_|inv_tok_)/.test(raw)) return true;
  if (/[A-Za-z0-9+/=]{48,}/.test(raw.replace(/[_.:|%~-]/g, ' ').replace(/\s+/g, ' '))) return true;
  return false;
}

function safeRouteValue(rule, value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw || /[\u0000-\u001f\u007f]/.test(raw) || looksLikeCredential(raw)) return '';
  if (rule === 'id') return /^[A-Za-z0-9_.:-]{1,128}$/.test(raw) ? raw : '';
  if (rule === 'slug') return /^[a-z0-9][a-z0-9_.-]{0,63}$/i.test(raw) ? raw : '';
  if (rule === 'int') return /^\d{1,6}$/.test(raw) ? raw : '';
  if (rule === 'label') return raw.length <= 80 && /^[\w .:@/+-]+$/.test(raw) ? raw : '';
  if (rule === 'search') return raw.length <= 120 ? raw : '';
  if (rule === 'date') return /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?)?$/.test(raw) ? raw : '';
  if (rule === 'group_key') return raw.length <= 640 && /^[A-Za-z0-9_.:%~!*'()|-]+$/.test(raw) ? raw : '';
  return '';
}

/** Keep only known route parameters with bounded, non-credential values. */
export function sanitizeRouteParams(input) {
  const params = input instanceof URLSearchParams ? input : new URLSearchParams(String(input ?? ''));
  const kept = new URLSearchParams();
  for (const [key, value] of params.entries()) {
    if (kept.has(key)) continue;
    if (INSPECTOR_PARAMS.has(key)) {
      if (key === ENTRY_PARAM ? INSPECTOR_ENTRIES.includes(value) : key === 'ev_family' ? PROVIDER_FAMILIES.includes(value) : isSafeInspectorId(value)) kept.set(key, value);
      continue;
    }
    const rule = ROUTE_PARAM_RULES[key];
    if (!rule || CREDENTIAL_NAME.test(key)) continue;
    const safe = safeRouteValue(rule, value);
    if (safe) kept.set(key, safe);
  }
  return kept;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

export function isSafeInspectorId(value) {
  return SAFE_ID.test(text(value));
}

/** Validate and normalize a ref. Returns null when the entry or a required id is missing or unsafe. */
export function normalizeInspectorRef(input) {
  const ref = record(input);
  if (!ref) return null;
  const entry = text(ref.entry);
  if (!INSPECTOR_ENTRIES.includes(entry)) return null;
  const out = { entry };
  for (const field of ALLOWED_FIELDS[entry]) {
    const value = text(ref[field]);
    if (!value) continue;
    if (field === 'family') {
      if (!PROVIDER_FAMILIES.includes(value)) return null;
    } else if (!isSafeInspectorId(value)) {
      return null;
    }
    out[field] = value;
  }
  for (const field of REQUIRED_FIELDS[entry]) {
    if (!out[field]) return null;
  }
  return out;
}

/** Stable identity for a ref; used for generation guards and selection highlighting. */
export function inspectorRefKey(input) {
  const ref = normalizeInspectorRef(input);
  if (!ref) return '';
  return [ref.entry, ...ALLOWED_FIELDS[ref.entry].map((field) => ref[field] ?? '')].join('|');
}

function splitHref(href) {
  const raw = text(href);
  const hashIndex = raw.indexOf('#');
  const prefix = hashIndex >= 0 ? raw.slice(0, hashIndex) : raw;
  const hash = hashIndex >= 0 ? raw.slice(hashIndex + 1) : '';
  const queryIndex = hash.indexOf('?');
  const route = queryIndex >= 0 ? hash.slice(0, queryIndex) : hash;
  const params = new URLSearchParams(queryIndex >= 0 ? hash.slice(queryIndex + 1) : '');
  return { prefix, route, params };
}

function joinHref({ prefix, route, params }) {
  const query = params.toString();
  return `${prefix}#${route}${query ? `?${query}` : ''}`;
}

/** Parse a ref from a hash (with or without the leading '#') or a full href. */
export function parseInspectorRef(hashOrHref) {
  const raw = text(hashOrHref);
  const { params } = splitHref(raw.includes('#') ? raw : `#${raw}`);
  const entry = params.get(ENTRY_PARAM);
  if (!entry) return null;
  const ref = { entry };
  for (const [field, param] of Object.entries(FIELD_PARAMS)) {
    const value = params.get(param);
    if (value) ref[field] = value;
  }
  return normalizeInspectorRef(ref);
}

/** Remove every inspector parameter from a hash or href, keeping route and page state. */
export function stripInspectorParams(hashOrHref) {
  const raw = text(hashOrHref);
  const parts = splitHref(raw.includes('#') ? raw : `#${raw}`);
  const kept = sanitizeRouteParams(parts.params);
  for (const key of INSPECTOR_PARAMS) kept.delete(key);
  parts.params = kept;
  const joined = joinHref(parts);
  return raw.includes('#') || !raw ? joined : joined.slice(1);
}

function currentHref() {
  if (typeof window === 'undefined' || !window.location) return '#';
  return `${window.location.pathname}${window.location.search}${window.location.hash || '#'}`;
}

/**
 * Address that opens `ref` over `baseHref` (default: the current page). Pass '/app#audit' or a
 * target/check canonical base for cross-page entry. Returns '' for an invalid ref.
 */
export function buildEvidenceInspectorHref(input, baseHref) {
  const ref = normalizeInspectorRef(input);
  if (!ref) return '';
  const parts = splitHref(stripInspectorParams(baseHref === undefined ? currentHref() : text(baseHref) || '#'));
  parts.params = sanitizeRouteParams(parts.params);
  parts.params.set(ENTRY_PARAM, ref.entry);
  for (const [field, param] of Object.entries(FIELD_PARAMS)) {
    if (ref[field]) parts.params.set(param, ref[field]);
  }
  return joinHref(parts);
}

function dispatchInspectorEvent(detail) {
  if (typeof window === 'undefined' || typeof window.dispatchEvent !== 'function') return;
  window.dispatchEvent(new CustomEvent(EVIDENCE_INSPECTOR_EVENT, { detail }));
}

function activeFocusKey() {
  if (typeof document === 'undefined') return '';
  const active = document.activeElement;
  if (!active || active === document.body) return '';
  const keyed = active.closest?.('[data-focus-key]');
  const key = keyed?.getAttribute('data-focus-key') || active.id || '';
  return isSafeInspectorId(key) ? key : '';
}

/**
 * Open the shared inspector over the current page: pushes one history entry so browser Back
 * closes the inspector before leaving the list. `options.focusKey` names the trigger to restore.
 */
export function openEvidenceInspector(input, options = {}) {
  const ref = normalizeInspectorRef(input);
  if (!ref || typeof window === 'undefined') return false;
  const href = buildEvidenceInspectorHref(ref);
  const previous = record(window.history.state) ?? {};
  const alreadyOpen = Boolean(parseInspectorRef(window.location.hash));
  const focusKey = isSafeInspectorId(options.focusKey) ? text(options.focusKey) : activeFocusKey();
  const state = {
    ...previous,
    astranullInspector: {
      pushed: alreadyOpen ? Boolean(record(previous.astranullInspector)?.pushed) : true,
      focusKey: alreadyOpen ? text(record(previous.astranullInspector)?.focusKey) || focusKey : focusKey,
    },
  };
  if (alreadyOpen) window.history.replaceState(state, '', href);
  else window.history.pushState(state, '', href);
  dispatchInspectorEvent({ action: 'open', ref });
  return true;
}

/** Switch the inspected record (Next/Previous member) without adding history entries. */
export function replaceEvidenceInspector(input) {
  const ref = normalizeInspectorRef(input);
  if (!ref || typeof window === 'undefined') return false;
  window.history.replaceState(window.history.state, '', buildEvidenceInspectorHref(ref));
  dispatchInspectorEvent({ action: 'replace', ref });
  return true;
}

/** Focus key recorded when the inspector opened, if any. */
export function inspectorOriginFocusKey() {
  if (typeof window === 'undefined') return '';
  return text(record(record(window.history.state)?.astranullInspector)?.focusKey);
}

/**
 * Close the inspector. When this page pushed the entry, go back (restores the exact prior
 * address); a cold deep link has nothing to go back to, so the parameters are replaced away.
 */
export function closeEvidenceInspector() {
  if (typeof window === 'undefined') return;
  const inspector = record(record(window.history.state)?.astranullInspector);
  if (inspector?.pushed && parseInspectorRef(window.location.hash)) {
    window.history.back();
    return;
  }
  const previous = record(window.history.state) ?? {};
  const { astranullInspector: _drop, ...rest } = previous;
  window.history.replaceState(rest, '', stripInspectorParams(currentHref()));
  dispatchInspectorEvent({ action: 'close', ref: null });
}

/** Exact read-only query for GET /v1/evidence-context. Never includes anything but ids. */
export function evidenceContextPath(input) {
  const ref = normalizeInspectorRef(input);
  if (!ref) return '';
  const params = new URLSearchParams({ entry: ref.entry });
  for (const field of ALLOWED_FIELDS[ref.entry]) {
    if (ref[field]) params.set(field, ref[field]);
  }
  return `/v1/evidence-context?${params.toString()}`;
}

/** Map a failed read to a distinct, honest state. 401 is handled by the shell's re-auth flow. */
export function classifyInspectorError(error) {
  const status = Number(record(error)?.status ?? record(record(error)?.payload)?.status);
  const code = text(record(record(error)?.payload)?.error);
  if (status === 403 || code === 'forbidden') {
    return { state: 'denied', permission: text(record(record(error)?.payload)?.permission) };
  }
  if (status === 404) {
    // The context route answers a missing or other-tenant record with state: not_found. A bare
    // 404 means this server has no such route, which is unavailability, not a missing record.
    const routeAnswered = text(record(record(error)?.payload)?.state) === 'not_found';
    return { state: routeAnswered || code.endsWith('_not_found') ? 'not_found' : 'route_missing', permission: '' };
  }
  if (status === 401) return { state: 'auth', permission: '' };
  return { state: 'unavailable', permission: '' };
}

const UNAVAILABLE_REASONS = new Set(['no_refs', 'fetch_failed', 'permission_denied', 'expired', 'partial']);

function summaryBlock(value) {
  const block = record(value);
  if (!block) return { status: 'not_recorded', fields: [] };
  const status = text(block.status) || 'recorded';
  const fields = [];
  for (const [key, raw] of Object.entries(block)) {
    if (key === 'status') continue;
    if (raw === null || raw === undefined || raw === '') continue;
    if (key === 'request_count') fields.push(...requestCountFields(record(raw)));
    else if (key === 'provenance') fields.push(...provenanceFields(record(raw)));
    if (typeof raw === 'object') continue;
    fields.push({ key, value: String(raw) });
  }
  return { status, fields };
}

/** Recorded request counts only; a missing count is "not recorded", never zero. */
function requestCountFields(count) {
  if (!count || text(count.status) !== 'recorded') return [{ key: 'request_count', value: 'Not recorded' }];
  const out = [];
  for (const key of ['requests_sent', 'requests_simulated']) {
    const value = Number(count[key]);
    if (count[key] !== null && count[key] !== undefined && Number.isFinite(value)) out.push({ key, value: String(value) });
  }
  return out.length ? out : [{ key: 'request_count', value: 'Not recorded' }];
}

function provenanceFields(provenance) {
  if (!provenance || text(provenance.status) !== 'recorded') return [{ key: 'provenance', value: 'Not recorded' }];
  const kind = text(provenance.kind).replace(/_/g, ' ') || 'recorded';
  const live = provenance.live_external === true ? 'live external' : provenance.live_external === false ? 'not live external evidence' : 'live status not recorded';
  return [{ key: 'provenance', value: `${kind} (${live})` }];
}

function observation(value, relationship) {
  const block = record(value);
  if (!block) return null;
  const integrity = record(block.integrity);
  return {
    testRunId: text(block.test_run_id),
    verdictId: text(block.verdict_id),
    evidenceIds: [...list(block.evidence_ids), block.evidence_id].map(text).filter(Boolean),
    observedAt: text(block.observed_at),
    relationship: text(block.relationship) || relationship,
    integrity: integrity
      ? {
        status: text(integrity.status) || 'not_recorded',
        verifiedAt: text(integrity.verified_at),
        method: text(integrity.method),
        refs: list(integrity.refs).map(record).filter(Boolean).map((ref) => ({
          evidenceId: text(ref.evidence_id),
          status: text(ref.status) || 'not_recorded',
          verifiedAt: text(ref.verified_at),
          method: text(ref.method),
        })),
      }
      : null,
    closesFinding: block.closes_finding === true,
  };
}

/**
 * Pure view model for the inspector renderer. Every absent field stays null/'' so the UI can say
 * "Not recorded"; nothing is substituted from a latest or first record.
 */
export function normalizeEvidenceContext(payload, input) {
  const ref = normalizeInspectorRef(input);
  const body = record(payload);
  if (!body) {
    return { state: 'unavailable', ref, missingEvidenceIds: [], proof: null, provider: { confidence: null, conflict: false, corpus: '', source: '' }, answer: null, primary: null, originating: null, later: null, alternatives: [], request: summaryBlock(null), response: summaryBlock(null), evaluation: summaryBlock(null), subject: {}, limitations: [], unavailableReason: 'fetch_failed' };
  }
  const answer = record(body.answer);
  const reason = text(body.unavailable_reason);
  const unavailableReason = UNAVAILABLE_REASONS.has(reason) ? reason : '';
  const primary = observation(body.primary, 'originating');
  const originating = observation(body.originating, 'originating');
  const later = observation(body.latest_distinct ?? body.latest_same_check, 'later_run_same_target_check');
  let state = 'ready';
  if (unavailableReason === 'permission_denied') state = 'denied';
  else if (unavailableReason === 'no_refs') state = 'no_refs';
  else if (unavailableReason === 'expired') state = 'expired';
  else if (unavailableReason === 'fetch_failed') state = 'unavailable';
  else if (unavailableReason === 'partial') state = 'partial';
  else if (!primary && !answer) state = 'no_refs';
  const subject = record(body.subject) ?? {};
  const proof = record(subject.proof);
  return {
    state,
    missingEvidenceIds: list(body.missing_evidence_ids).map(text).filter(Boolean),
    proof: proof
      ? Object.fromEntries(['methods', 'matched_signals', 'cnames', 'addresses', 'fingerprints'].map((key) => [
        key,
        list(proof[key]).map((item) => (typeof item === 'string' ? item.trim() : text(record(item)?.signal ?? record(item)?.value ?? record(item)?.name))).filter(Boolean).slice(0, 12),
      ]))
      : null,
    provider: {
      confidence: subject.confidence === null || subject.confidence === undefined || subject.confidence === '' || !Number.isFinite(Number(subject.confidence)) ? null : Number(subject.confidence),
      conflict: subject.conflict === true,
      corpus: text(subject.corpus),
      source: text(subject.source),
    },
    ref,
    subject: Object.fromEntries(Object.entries(subject).filter(([, value]) => typeof value === 'string' && value).map(([key, value]) => [key, value])),
    answer: answer
      ? {
        outcome: text(answer.outcome),
        explanation: text(answer.explanation),
        expected: text(answer.expected_behavior),
        observed: text(answer.observed_behavior),
      }
      : null,
    limitations: list(answer?.limitations).map(text).filter(Boolean),
    primary,
    originating,
    later: later && primary && later.testRunId && later.testRunId === primary.testRunId && later.verdictId === primary.verdictId ? null : later,
    alternatives: list(body.alternatives).map((item) => observation(item, 'alternative')).filter(Boolean),
    request: summaryBlock(body.request_summary),
    response: summaryBlock(body.response_summary),
    evaluation: summaryBlock(body.evaluation),
    unavailableReason,
  };
}

/**
 * Identity of a committed inspector load: the reading scope (tenant/user/role) plus the ref. A
 * model is only readable while both still match, so a scope change hides it in the same render.
 */
export function inspectorLoadKey(scopeKey, refKey) {
  return refKey ? `${text(scopeKey)}::${text(refKey)}` : '';
}

/**
 * Late-response guard. Each `begin` invalidates earlier tokens; `isCurrent(token)` is false for a
 * response that arrives after the selection, tenant, or user changed.
 */
export function createInspectorGeneration() {
  let counter = 0;
  let current = '';
  return {
    begin(scopeKey, refKey) {
      counter += 1;
      current = `${text(scopeKey)}|${text(refKey)}|${counter}`;
      return current;
    },
    isCurrent(token) {
      return Boolean(token) && token === current;
    },
    cancel() {
      counter += 1;
      current = '';
    },
  };
}

const LIMITATION_COPY = Object.freeze({
  external_only: 'Observed from outside only; nothing inside your network was inspected.',
  bounded_check_not_capacity: 'A bounded check does not measure volumetric capacity.',
});

export function limitationLabel(code) {
  return LIMITATION_COPY[text(code)] ?? text(code).replace(/_/g, ' ');
}

/** Existing exact-ID reads used only when GET /v1/evidence-context does not answer. */
export function fallbackRecordPath(input) {
  const ref = normalizeInspectorRef(input);
  if (!ref) return '';
  if (ref.entry === 'finding' || ref.entry === 'group_member') return `/v1/findings/${encodeURIComponent(ref.finding_id)}`;
  if (ref.entry === 'check_result') return `/v1/test-runs/${encodeURIComponent(ref.test_run_id)}`;
  if (ref.entry === 'provider') return `/v1/targets/${encodeURIComponent(ref.target_id)}`;
  if (ref.entry === 'artifact') return `/v1/evidence/${encodeURIComponent(ref.evidence_id)}`;
  if (ref.entry === 'report') return `/v1/reports/${encodeURIComponent(ref.report_id)}`;
  return '';
}

function verdictOf(run) {
  const verdict = record(run?.verdict);
  return verdict ?? (typeof run?.verdict === 'string' ? { verdict: run.verdict } : null);
}

/**
 * Shape an exact record into the evidence-context payload. Only fields recorded on that record
 * are used; request/response stay not_recorded and the result is always marked partial.
 * Returns { payload, mismatch } where mismatch means the record does not belong to the ref.
 */
export function fallbackContextFromRecord(input, source) {
  const ref = normalizeInspectorRef(input);
  const body = record(source);
  if (!ref || !body) return { payload: null, mismatch: false };
  const base = {
    entry: ref.entry,
    alternatives: [],
    request_summary: { status: 'not_recorded' },
    response_summary: { status: 'not_recorded' },
    evaluation: { status: 'not_recorded' },
    unavailable_reason: 'partial',
    source: 'record_fallback',
  };
  if (ref.entry === 'finding' || ref.entry === 'group_member') {
    if (text(body.id) !== ref.finding_id) return { payload: null, mismatch: true };
    const evidenceIds = list(body.evidence_ids).map(text).filter(Boolean);
    const verdictId = text(body.verdict_id);
    const lastVerdictId = text(body.last_verdict_id);
    return {
      mismatch: false,
      payload: {
        ...base,
        subject: { finding_id: ref.finding_id, target_id: text(body.target_id), check_id: text(body.check_id), title: text(body.title), lifecycle: text(body.status) || text(body.state), severity: text(body.severity) },
        answer: null,
        primary: text(body.test_run_id) || verdictId || evidenceIds.length
          ? { test_run_id: text(body.test_run_id), verdict_id: verdictId, evidence_ids: evidenceIds, observed_at: text(body.created_at), integrity: null }
          : null,
        latest_distinct: lastVerdictId && lastVerdictId !== verdictId
          ? { verdict_id: lastVerdictId, test_run_id: '', evidence_ids: [], observed_at: text(body.updated_at), relationship: 'later_verdict_same_finding' }
          : null,
        unavailable_reason: evidenceIds.length || text(body.test_run_id) ? 'partial' : 'no_refs',
      },
    };
  }
  if (ref.entry === 'check_result') {
    const runTarget = text(body.target_id);
    const runCheck = text(body.check_id);
    if (text(body.id) !== ref.test_run_id || (runTarget && runTarget !== ref.target_id) || (runCheck && runCheck !== ref.check_id)) {
      return { payload: null, mismatch: true };
    }
    // The address only hints at target and check; the record must state both to be shown as this result.
    if (!runTarget || !runCheck) return { payload: null, mismatch: false, unbound: true };
    const verdict = verdictOf(body);
    const evidenceIds = list(verdict?.evidence_ids ?? body.evidence_ids).map(text).filter(Boolean);
    return {
      mismatch: false,
      payload: {
        ...base,
        subject: { target_id: runTarget, check_id: runCheck, test_run_id: ref.test_run_id, run_status: text(body.status) },
        answer: verdict
          ? { outcome: text(verdict.verdict ?? verdict.result), explanation: text(verdict.explanation), limitations: ['external_only', 'bounded_check_not_capacity'] }
          : null,
        primary: { test_run_id: ref.test_run_id, verdict_id: text(verdict?.id ?? verdict?.verdict_id), evidence_ids: evidenceIds, observed_at: text(body.completed_at ?? verdict?.created_at ?? body.started_at), integrity: null },
        latest_distinct: null,
        unavailable_reason: verdict ? (evidenceIds.length ? 'partial' : 'no_refs') : 'partial',
      },
    };
  }
  if (ref.entry === 'provider') {
    const target = record(body.target);
    if (!target || !text(target.id)) return { payload: null, mismatch: false, unbound: true };
    if (text(target.id) !== ref.target_id) return { payload: null, mismatch: true };
    const profile = record(body.protection_profile);
    const familyRow = record(record(profile?.families)?.[ref.family]);
    const edge = record(body.edge_detection);
    const legacy = ['waf', 'cdn', 'cloud'].includes(ref.family) ? record(edge?.[ref.family]) : null;
    const layer = list(edge?.layers).map(record).find((row) => row && text(row.family) === ref.family) ?? null;
    const row = familyRow ?? legacy;
    const status = text(row?.status) || (ref.family === 'dns' || ref.family === 'origin_hosting' ? 'unknown' : edge ? 'not_recorded' : 'not_checked');
    const provider = text(row?.provider ?? row?.vendor) || (familyRow ? '' : text(layer?.provider));
    const sources = list(familyRow?.sources ?? layer?.sources).map(text).filter(Boolean);
    const observedAt = text(familyRow?.observed_at ?? edge?.observed_at);
    const runId = text(familyRow?.test_run_id ?? edge?.test_run_id);
    return {
      mismatch: false,
      payload: {
        ...base,
        subject: { target_id: ref.target_id, family: ref.family, target_value: text(target?.value) },
        answer: { outcome: status, explanation: provider ? `Provider recorded: ${provider}` : '', limitations: ['external_only'] },
        primary: runId || observedAt
          ? { test_run_id: runId, verdict_id: '', evidence_ids: list(familyRow?.evidence_ids).map(text).filter(Boolean), observed_at: observedAt, integrity: null }
          : null,
        evaluation: {
          status: sources.length ? 'recorded' : 'not_recorded',
          ...(provider ? { provider } : {}),
          ...(sources.length ? { sources: sources.join(', ') } : {}),
          ...(familyRow && familyRow.confidence !== null && familyRow.confidence !== undefined && familyRow.confidence !== '' && Number.isFinite(Number(familyRow.confidence)) ? { confidence: String(familyRow.confidence) } : {}),
          ...(text(familyRow?.freshness) ? { freshness: text(familyRow.freshness) } : {}),
        },
        latest_distinct: null,
        unavailable_reason: row ? 'partial' : 'no_refs',
      },
    };
  }
  if (ref.entry === 'artifact') {
    if (text(body.id) !== ref.evidence_id) return { payload: null, mismatch: true };
    const artifactRun = text(body.test_run_id);
    if (ref.test_run_id && artifactRun && artifactRun !== ref.test_run_id) return { payload: null, mismatch: true };
    if (ref.test_run_id && !artifactRun) return { payload: null, mismatch: false, unbound: true };
    const digest = text(body.sha256 ?? body.content_sha256);
    return {
      mismatch: false,
      payload: {
        ...base,
        subject: { evidence_id: ref.evidence_id, label: text(body.label ?? body.kind), test_run_id: artifactRun },
        answer: null,
        primary: { test_run_id: artifactRun, verdict_id: '', evidence_ids: [ref.evidence_id], observed_at: text(body.created_at), integrity: { status: digest ? 'recorded_digest' : 'not_recorded' } },
        latest_distinct: null,
      },
    };
  }
  if (ref.entry === 'report') {
    if (text(body.id) !== ref.report_id) return { payload: null, mismatch: true };
    const runIds = list(body.run_ids).map(text).filter(Boolean);
    return {
      mismatch: false,
      payload: {
        ...base,
        subject: { report_id: ref.report_id, title: text(body.title), kind: text(body.kind) },
        answer: null,
        primary: runIds.length ? { test_run_id: runIds.join(', '), verdict_id: '', evidence_ids: [], observed_at: text(body.created_at), integrity: null } : null,
        latest_distinct: null,
        unavailable_reason: runIds.length ? 'partial' : 'no_refs',
      },
    };
  }
  return { payload: null, mismatch: false };
}
