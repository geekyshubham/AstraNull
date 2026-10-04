import { createHash } from 'node:crypto';
import { targetKindCompatibilityError } from './checkTargetCompatibility.mjs';
import { ATTACK_SURFACE_DOMAINS, ATTACK_VECTOR_REGISTRY } from './resourceExhaustionTaxonomy.mjs';
import { nextPolicyRunAt, normalizePolicyTimezone, PolicyValidationError } from './testPolicyManagement.mjs';

export const SCAN_STATUSES = Object.freeze(['scheduled', 'pending', 'running', 'completed', 'denied', 'cancelled']);
export const ACTIVE_SCAN_STATUSES = Object.freeze(['pending', 'running']);
export const CANCELLABLE_SCAN_STATUSES = Object.freeze(['scheduled', 'pending', 'running']);
export const TERMINAL_SCAN_STATUSES = Object.freeze(['completed', 'denied', 'cancelled']);
export const STEP_STATUSES = Object.freeze([
  'pending', 'deferred', 'starting', 'running', 'collecting', 'verdicted', 'denied', 'skipped', 'cancelled',
]);
export const ACTIVE_STEP_STATUSES = Object.freeze(['starting', 'running', 'collecting']);
export const TERMINAL_STEP_STATUSES = Object.freeze(['verdicted', 'denied', 'skipped', 'cancelled']);
export const SCAN_RECURRENCE_CADENCES = Object.freeze(['daily', 'weekly', 'monthly']);
// Sized so one "run all checks" scan can cover the full customer catalog for one target, and so
// one scan's run ids never exceed the 500-id Postgres evidence batch used by scan projection.
export const MAX_SCAN_CHECKS = 500;
export const MAX_SCAN_STEPS = 500;
export const MAX_SCAN_NAME_LENGTH = 120;
export const MAX_CANCEL_REASON_LENGTH = 500;
export const MIN_SCHEDULE_LEAD_MS = 60_000;
export const SCAN_LEASE_MS = 60_000;
export const MAX_STEP_START_ATTEMPTS = 2;

export const SCAN_AUDIT_ACTIONS = Object.freeze({
  created: 'validation_scan.created',
  createDenied: 'validation_scan.create_denied',
  cancelDenied: 'validation_scan.cancel_denied',
  scheduled: 'validation_scan.scheduled',
  updated: 'validation_scan.updated',
  dispatched: 'validation_scan.dispatched',
  scheduleDenied: 'validation_scan.schedule_denied',
  stepStarted: 'validation_scan.step_started',
  stepDeferred: 'validation_scan.step_deferred',
  stepDenied: 'validation_scan.step_denied',
  stepSkipped: 'validation_scan.step_skipped',
  stepCompleted: 'validation_scan.step_completed',
  cancelled: 'validation_scan.cancelled',
  seriesStopped: 'validation_scan.series_stopped',
  completed: 'validation_scan.completed',
  advanceFailed: 'validation_scan.advance_failed',
  advanceBlocked: 'validation_scan.advance_blocked',
  dispatchFailed: 'validation_scan.dispatch_failed',
  orphanRunCancelled: 'validation_scan.orphan_run_cancelled',
});

export const SCHEDULED_SCAN_ACTOR_ID = 'validation-scan-scheduler';
const HOUR_MS = 3_600_000;
const HOURLY_CAP_DENIALS = new Set(['safe_rate_cap_exceeded', 'entitlement_limit_exceeded']);
const DEFER_DENIALS = new Set(['safe_min_interval_active', ...HOURLY_CAP_DENIALS]);
const ABORT_DENIALS = new Set([
  'safe_window_closed',
  'kill_switch_active',
  'tenant_suspended',
  'target_group_not_found',
  'concurrent_run_blocked',
  'scan_dispatch_invalid',
]);
const STEP_DENIALS = new Set([
  'soc_gated_check',
  'unknown_check',
  'target_not_found',
  'missing_target_id',
  'target_kind_not_supported',
  'prerequisites_not_met',
  'ownership_not_verified',
  'missing_target_bound_direct_address',
  'event_cap_exceeded',
  'target_binding_changed',
  'test_policy_not_found',
  'test_policy_disabled',
  'test_policy_binding_mismatch',
]);

export class ScanValidationError extends Error {
  constructor(field, message, code = 'invalid_validation_scan', status = 400) {
    super(message);
    this.name = 'ScanValidationError';
    this.field = field;
    this.code = code;
    this.status = status;
  }

  toResponse() {
    return { error: this.code, status: this.status, field: this.field, message: this.message };
  }
}

export function scanValidationResponse(error) {
  if (error instanceof ScanValidationError) return error.toResponse();
  if (error instanceof PolicyValidationError) return { ...error.toResponse(), error: 'invalid_validation_scan' };
  throw error;
}

function normalizeIsoTimestamp(value, field) {
  const date = value instanceof Date ? value : new Date(String(value ?? ''));
  if (Number.isNaN(date.getTime())) throw new ScanValidationError(field, `${field} must be a valid ISO-8601 timestamp.`);
  return date;
}

export function normalizeScanRecurrence(value) {
  if (value == null || value === '' || value === 'none') return null;
  const raw = typeof value === 'string' ? { cadence: value } : value;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ScanValidationError('recurrence', 'recurrence must be an object with a cadence.');
  }
  const cadence = String(raw.cadence ?? '').trim().toLowerCase();
  if (cadence === '' || cadence === 'none') return null;
  if (!SCAN_RECURRENCE_CADENCES.includes(cadence)) {
    throw new ScanValidationError('recurrence', `Unsupported recurrence cadence: ${cadence}`);
  }
  return { cadence, timezone: normalizePolicyTimezone(raw.timezone, 'recurrence.timezone') };
}

export function normalizeCheckIds(value) {
  if (!Array.isArray(value)) throw new ScanValidationError('check_ids', 'check_ids must be a non-empty array of check ids.');
  const ids = [...new Set(value.map((id) => String(id ?? '').trim()).filter(Boolean))];
  if (!ids.length) throw new ScanValidationError('check_ids', 'Select at least one check.');
  if (ids.length > MAX_SCAN_CHECKS) {
    throw new ScanValidationError('check_ids', `Select at most ${MAX_SCAN_CHECKS} checks per scan.`);
  }
  return ids;
}

function normalizeScanName(value) {
  if (value == null) return null;
  const name = String(value).trim();
  if (!name) return null;
  if (name.length > MAX_SCAN_NAME_LENGTH) {
    throw new ScanValidationError('name', `name must be at most ${MAX_SCAN_NAME_LENGTH} characters.`);
  }
  return name;
}

export function normalizeCancelReason(value) {
  if (value == null) return null;
  const reason = String(value).trim();
  if (!reason) return null;
  return reason.slice(0, MAX_CANCEL_REASON_LENGTH);
}

export function normalizeScanInput(body = {}, { now = Date.now(), partial = false } = {}) {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ScanValidationError('body', 'Request body must be a JSON object.');
  }
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const normalized = {};
  const has = (key) => Object.prototype.hasOwnProperty.call(body, key);

  if (!partial || has('target_group_id')) {
    const targetGroupId = String(body.target_group_id ?? '').trim();
    if (!targetGroupId) throw new ScanValidationError('target_group_id', 'target_group_id is required.');
    normalized.target_group_id = targetGroupId;
  }
  if (!partial || has('target_id')) {
    const targetId = String(body.target_id ?? '').trim();
    normalized.target_id = targetId || null;
  }
  if (!partial || has('check_ids')) normalized.check_ids = normalizeCheckIds(body.check_ids);
  if (!partial || has('name')) normalized.name = normalizeScanName(body.name);
  if (!partial || has('scheduled_for')) {
    if (body.scheduled_for == null || body.scheduled_for === '') {
      normalized.scheduled_for = null;
    } else {
      const scheduled = normalizeIsoTimestamp(body.scheduled_for, 'scheduled_for');
      if (scheduled.getTime() < nowMs + MIN_SCHEDULE_LEAD_MS) {
        throw new ScanValidationError('scheduled_for', 'scheduled_for must be at least one minute in the future.');
      }
      normalized.scheduled_for = scheduled.toISOString();
    }
  }
  if (!partial || has('recurrence')) normalized.recurrence = normalizeScanRecurrence(body.recurrence);
  if (!partial && normalized.recurrence && !normalized.scheduled_for) {
    throw new ScanValidationError('recurrence', 'A recurring scan needs a scheduled_for time for its first occurrence.');
  }
  return normalized;
}

function protocolForProbeProfile(profile = {}) {
  const kind = String(profile.kind ?? '');
  if (kind.startsWith('dns')) return 'dns';
  if (kind === 'udp_probe') return 'udp';
  if (kind.startsWith('tls')) return 'tls';
  if (kind.startsWith('quic') || kind.startsWith('http3')) return 'quic';
  if (kind === 'port_scan_bounded' || kind === 'tcp_connect') return 'tcp';
  if (kind === 'metadata_marker' || kind === 'ops_readiness') return 'none';
  if (profile.use_https === false) return 'http';
  return 'https';
}

export function requestSnapshotForCheck(check) {
  const profile = check?.probe_profile ?? {};
  const paths = Array.isArray(profile.paths) ? profile.paths : [];
  return {
    kind: profile.kind ?? null,
    method: profile.http_method ?? profile.method ?? null,
    path: profile.probe_path ?? paths[0] ?? profile.graphql_path ?? profile.grpc_path ?? null,
    protocol: protocolForProbeProfile(profile),
    max_requests: profile.max_requests ?? null,
    timeout_ms: profile.timeout_ms ?? null,
  };
}

export function planScanSteps({ checks, targets, targetId = null }) {
  const scopedTargets = targetId ? targets.filter((target) => target.id === targetId) : targets;
  const steps = [];
  const excluded = [];
  for (const check of checks) {
    for (const target of scopedTargets) {
      const compatibility = targetKindCompatibilityError(check, target);
      if (compatibility) {
        excluded.push({
          check_id: check.check_id,
          target_id: target.id,
          reason: 'target_kind_not_supported',
          target_kind: compatibility.target_kind,
          supported_targets: compatibility.supported_targets,
        });
        continue;
      }
      steps.push({
        position: steps.length,
        check_id: check.check_id,
        target_id: target.id,
        request_snapshot: requestSnapshotForCheck(check),
      });
    }
  }
  if (steps.length > MAX_SCAN_STEPS) {
    throw new ScanValidationError('check_ids', `A scan may plan at most ${MAX_SCAN_STEPS} check/target steps.`, 'scan_too_large');
  }
  return { steps, excluded };
}

export function classifyStartDenial(result) {
  const code = typeof result === 'string' ? result : result?.error;
  if (!code) return 'retry';
  if (DEFER_DENIALS.has(code)) return 'defer';
  if (ABORT_DENIALS.has(code)) return 'abort';
  if (STEP_DENIALS.has(code)) return 'step';
  const status = typeof result === 'object' ? Number(result?.status) : NaN;
  if (Number.isFinite(status) && status >= 400 && status < 500) return 'step';
  return 'retry';
}

/**
 * When a deferred step may retry. Hourly caps clear once the oldest run in the rolling hour ages out;
 * the minimum interval clears relative to the group's most recent run.
 */
export function deferredStepEligibleAt({
  code,
  runs = [],
  tenantId,
  targetGroupId,
  minSecondsBetweenRuns = 0,
  now = new Date(),
}) {
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  const createdMs = (run) => new Date(run.created_at).getTime();
  const tenantRuns = runs.filter((run) => run?.tenant_id === tenantId && Number.isFinite(createdMs(run)));
  if (HOURLY_CAP_DENIALS.has(code)) {
    const windowStart = nowMs - HOUR_MS;
    const oldest = tenantRuns.map(createdMs).filter((ms) => ms >= windowStart).sort((a, b) => a - b)[0] ?? nowMs;
    return new Date(Math.max(nowMs + 1000, oldest + HOUR_MS + 1000)).toISOString();
  }
  const prior = tenantRuns
    .filter((run) => run.target_group_id === targetGroupId)
    .sort((left, right) => createdMs(right) - createdMs(left))[0];
  const base = prior ? createdMs(prior) : nowMs;
  return new Date(base + Math.max(1, Number(minSecondsBetweenRuns) || 0) * 1000).toISOString();
}

export function isHourlyCapDenial(code) {
  return HOURLY_CAP_DENIALS.has(code);
}

export function scanExecutionContext(scan) {
  if (scan.scheduled_for) {
    return {
      tenantId: scan.tenant_id,
      userId: SCHEDULED_SCAN_ACTOR_ID,
      role: 'system',
      via: 'validation_scan',
      on_behalf_of: scan.created_by ?? null,
    };
  }
  return { tenantId: scan.tenant_id, userId: scan.created_by, role: scan.created_by_role, via: 'validation_scan' };
}

export function computeScanSummary(steps = []) {
  const summary = {
    total: steps.length,
    pending: 0,
    deferred: 0,
    running: 0,
    verdicted: 0,
    denied: 0,
    skipped: 0,
    cancelled: 0,
  };
  for (const step of steps) {
    if (step.status === 'pending') summary.pending += 1;
    else if (step.status === 'deferred') summary.deferred += 1;
    else if (ACTIVE_STEP_STATUSES.includes(step.status)) summary.running += 1;
    else if (step.status === 'verdicted') summary.verdicted += 1;
    else if (step.status === 'denied') summary.denied += 1;
    else if (step.status === 'skipped') summary.skipped += 1;
    else if (step.status === 'cancelled') summary.cancelled += 1;
  }
  summary.completed = summary.verdicted + summary.denied + summary.skipped + summary.cancelled;
  return summary;
}

export function deriveScanStatus(steps = []) {
  if (!steps.length) return 'denied';
  if (!steps.every((step) => TERMINAL_STEP_STATUSES.includes(step.status))) return 'running';
  return steps.some((step) => step.status === 'verdicted') ? 'completed' : 'denied';
}

export function isScanActive(scan) {
  return ACTIVE_SCAN_STATUSES.includes(scan?.status);
}

export function isStepTerminal(step) {
  return TERMINAL_STEP_STATUSES.includes(step?.status);
}

export function nextScanOccurrenceAt(recurrence, from) {
  const normalized = normalizeScanRecurrence(recurrence);
  if (!normalized) return null;
  return nextPolicyRunAt(
    { cadence: normalized.cadence, timezone: normalized.timezone, enabled: true, state: 'active', safe_windows: [] },
    { from: from instanceof Date ? from : new Date(from), initial: false },
  );
}

/**
 * The next occurrence strictly after `now`, preserving the series' wall-clock cadence alignment.
 *
 * Starts from `from` (normally the just-run occurrence's scheduled_for) and advances one cadence
 * step at a time until the result is after `now`. On-time and slightly-late runs return exactly the
 * next aligned slot (no clock drift). After long scheduler downtime this collapses the missed
 * backlog into a single future run instead of replaying every missed occurrence back-to-back.
 *
 * @param {unknown} recurrence
 * @param {Date|string|number} from
 * @param {Date|string|number} now
 * @param {number} [maxSteps] safety cap on iterations
 * @returns {string|null} ISO timestamp or null when the recurrence produces no next run
 */
export function nextScanOccurrenceAfter(recurrence, from, now, maxSteps = 4000) {
  const nowMs = (now instanceof Date ? now : new Date(now)).getTime();
  let cursor = from instanceof Date ? from : new Date(from);
  for (let step = 0; step < maxSteps; step += 1) {
    const nextIso = nextScanOccurrenceAt(recurrence, cursor);
    if (!nextIso) return null;
    const nextMs = new Date(nextIso).getTime();
    if (nextMs > nowMs) return nextIso;
    // Defensive: a cadence must strictly advance. If it ever returns a non-advancing time, stop
    // rather than spin, and let the fallback below place the next slot after now.
    if (nextMs <= cursor.getTime()) break;
    cursor = new Date(nextIso);
  }
  // Cap hit (e.g. sub-daily cadence after years of downtime): fall back to the next slot after now.
  return nextScanOccurrenceAt(recurrence, new Date(nowMs));
}

export function scanOccurrenceKey(tenantId, seriesId, scheduledFor) {
  const scheduled = normalizeIsoTimestamp(scheduledFor, 'scheduled_for');
  return createHash('sha256')
    .update(`${tenantId} ${seriesId} ${scheduled.toISOString()}`)
    .digest('hex');
}

let sectionByCheckId = null;

function buildSectionIndex() {
  const domains = new Map(ATTACK_SURFACE_DOMAINS.map((domain) => [domain.id, domain.label]));
  const votes = new Map();
  for (const entry of ATTACK_VECTOR_REGISTRY) {
    const domainId = entry.domain ?? null;
    if (!domainId || !domains.has(domainId)) continue;
    for (const checkId of entry.check_ids ?? []) {
      if (!votes.has(checkId)) votes.set(checkId, new Map());
      const perCheck = votes.get(checkId);
      perCheck.set(domainId, (perCheck.get(domainId) ?? 0) + 1);
    }
  }
  const index = new Map();
  for (const [checkId, perCheck] of votes) {
    const [domainId] = [...perCheck.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))[0];
    index.set(checkId, { section_id: domainId, section_label: domains.get(domainId) });
  }
  return index;
}

export function sectionForCheck(checkId) {
  if (!sectionByCheckId) sectionByCheckId = buildSectionIndex();
  return sectionByCheckId.get(checkId) ?? null;
}

export function withCheckSection(check) {
  if (!check) return check;
  const section = sectionForCheck(check.check_id);
  return {
    ...check,
    section_id: section?.section_id ?? null,
    section_label: section?.section_label ?? null,
  };
}

function probeResultEventForRun(run, events = []) {
  if (!run) return null;
  const nonceHash = run.correlation?.nonce_hash ?? null;
  const candidates = events.filter((event) => event.test_run_id === run.id && event.signal_type === 'probe_result');
  return candidates.find((event) => nonceHash && event.nonce_hash === nonceHash) ?? candidates[0] ?? null;
}

function requestCountForProbeEvent(event, check) {
  if (!event) return { requests_sent: null, duration_ms: null, simulated: false, inline: false };
  const metadata = event.metadata ?? {};
  const attestation = metadata.safety_attestation ?? null;
  if (attestation && typeof attestation === 'object') {
    const sent = attestation.probe_requests_sent ?? attestation.requests_sent ?? null;
    return {
      requests_sent: Number.isFinite(Number(sent)) ? Number(sent) : null,
      duration_ms: Number.isFinite(Number(attestation.duration_ms)) ? Number(attestation.duration_ms) : null,
      simulated: false,
      inline: false,
    };
  }
  if (metadata.simulation === 'SAFE_PROBE_SIMULATION' || event.producer_kind === 'internal_simulation') {
    return { requests_sent: 0, duration_ms: null, simulated: true, inline: false };
  }
  if (metadata.probe_kind === 'ops_readiness' || check?.probe_profile?.kind === 'ops_readiness') {
    return { requests_sent: 0, duration_ms: null, simulated: false, inline: true };
  }
  return { requests_sent: null, duration_ms: null, simulated: false, inline: false };
}

export function projectScanStep({ step, check, target, run, verdict, events = [], probeJob = null }) {
  const probeEvent = probeResultEventForRun(run, events);
  const metadata = probeEvent?.metadata ?? {};
  const snapshot = step.request_snapshot ?? requestSnapshotForCheck(check);
  const boundProfile = probeJob?.probe_profile ?? null;
  const section = sectionForCheck(step.check_id);
  const counts = requestCountForProbeEvent(probeEvent, check);
  return {
    step_id: step.id,
    position: step.position,
    status: step.status,
    check_id: step.check_id,
    check_name: check?.name ?? step.check_name ?? step.check_id,
    vector_family: check?.vector_family ?? null,
    evidence_tier: check?.evidence_tier ?? null,
    section_id: section?.section_id ?? null,
    section_label: section?.section_label ?? null,
    target_id: step.target_id,
    target_kind: target?.kind ?? null,
    target_value: target?.value ?? null,
    test_run_id: step.test_run_id ?? null,
    run_status: run?.status ?? null,
    collection_deadline_at: run?.collection_deadline_at ?? null,
    error_code: step.error_code ?? null,
    skip_reason: step.skip_reason ?? null,
    eligible_at: step.eligible_at ?? null,
    attempts: step.attempts ?? 0,
    started_at: step.started_at ?? null,
    completed_at: step.completed_at ?? null,
    request: {
      kind: boundProfile?.kind ?? snapshot.kind ?? null,
      method: metadata.http_method ?? snapshot.method ?? null,
      path: boundProfile?.probe_path ?? boundProfile?.paths?.[0] ?? snapshot.path ?? null,
      protocol: snapshot.protocol ?? null,
      max_requests: probeJob?.constraints?.max_probe_requests ?? boundProfile?.max_requests ?? snapshot.max_requests ?? null,
      timeout_ms: boundProfile?.timeout_ms ?? snapshot.timeout_ms ?? null,
    },
    response: {
      external_result: run?.probe_external_result ?? probeEvent?.external_result ?? metadata.external_result ?? null,
      status_code: metadata.status_code ?? metadata.response_status ?? null,
      received_at: probeEvent?.timestamp ?? null,
    },
    requests_sent: counts.requests_sent,
    duration_ms: counts.duration_ms,
    requests_simulated: counts.simulated,
    requests_inline: counts.inline,
    verdict: verdict
      ? {
          verdict: verdict.verdict,
          confidence: verdict.confidence,
          explanation: verdict.explanation,
          severity: verdict.severity ?? null,
          placement_confidence: verdict.placement_confidence?.level ?? null,
        }
      : null,
  };
}

const ACTIVITY_METADATA_ALLOWLIST = [
  'external_result',
  'status_code',
  'requests_sent',
  'verdict',
  'confidence',
  'error_code',
  'reason',
  'eligible_at',
  'code',
  'scheduled_for',
  'step_count',
  'skipped_steps',
  'cancelled_steps',
  'changed_fields',
  'summary',
  'abort_reason',
  'status',
];

const ACTIVITY_OPENER_ACTIONS = new Set([
  SCAN_AUDIT_ACTIONS.created,
  SCAN_AUDIT_ACTIONS.scheduled,
  SCAN_AUDIT_ACTIONS.updated,
  SCAN_AUDIT_ACTIONS.dispatched,
  SCAN_AUDIT_ACTIONS.stepDeferred,
  SCAN_AUDIT_ACTIONS.stepDenied,
  SCAN_AUDIT_ACTIONS.stepSkipped,
  SCAN_AUDIT_ACTIONS.scheduleDenied,
  'test_run.started',
  'probe_job.created',
]);

function allowlistedMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') return {};
  const out = {};
  for (const key of ACTIVITY_METADATA_ALLOWLIST) {
    if (metadata[key] !== undefined) out[key] = metadata[key];
  }
  return out;
}

function describeAuditAction(action, metadata = {}) {
  const suffix = action.split('.').slice(1).join('.');
  const readable = suffix.replace(/_/g, ' ');
  if (metadata.error_code) return `${readable}: ${metadata.error_code}`;
  if (metadata.code) return `${readable}: ${metadata.code}`;
  if (metadata.verdict) return `${readable}: ${metadata.verdict}`;
  return readable;
}

function describeEvent(event) {
  if (event.signal_type === 'probe_activity' && event.producer_kind === 'signed_probe') {
    const activity = event.metadata?.activity ?? {};
    return [String(activity.stage ?? 'activity').replace(/_/g, ' '), activity.method ?? activity.operation,
      activity.status_code != null ? `HTTP ${activity.status_code}` : activity.error_class ?? activity.reason].filter(Boolean).join(': ');
  }
  if (event.signal_type === 'probe_result') {
    const result = event.external_result ?? event.metadata?.external_result ?? 'unknown';
    return `probe result received: ${result}`;
  }
  if (event.signal_type === 'agent_observation') return 'agent observation received';
  if (event.signal_type === 'agent_no_observation') return 'observation window elapsed without agent observation';
  return `${String(event.signal_type ?? 'event').replace(/_/g, ' ')} received`;
}

function eventIngestKey(event, index) {
  if (Number.isFinite(event.ingest_index)) return [Number(event.ingest_index), String(event.id ?? '')];
  const ingestedMs = new Date(event.ingested_at ?? event.timestamp ?? '').getTime();
  return [Number.isFinite(ingestedMs) ? ingestedMs : index, String(event.id ?? '')];
}

function compareKeys(left, right) {
  return left[0] - right[0] || left[1].localeCompare(right[1]);
}

/**
 * Activity items keep display order by event time, while the returned cursor tracks ingestion order
 * (audit sequence plus event ingestion key) so late-arriving observations with earlier timestamps
 * are never skipped by a client that polls with `after`.
 */
export function encodeActivityCursor({ auditSequence = 0, eventKey = null } = {}) {
  return `c1.${Buffer.from(JSON.stringify({ a: auditSequence, e: eventKey })).toString('base64url')}`;
}

export function decodeActivityCursor(value) {
  const raw = String(value ?? '');
  if (!raw.startsWith('c1.')) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw.slice(3), 'base64url').toString('utf8'));
    const auditSequence = Number(parsed?.a);
    const eventKey = Array.isArray(parsed?.e) && Number.isFinite(Number(parsed.e[0]))
      ? [Number(parsed.e[0]), String(parsed.e[1] ?? '')]
      : null;
    if (!Number.isFinite(auditSequence)) return null;
    return { auditSequence, eventKey };
  } catch {
    return null;
  }
}

function stripIngest(item) {
  const { ingest: _ingest, ...rest } = item;
  return rest;
}

function cursorAfter(items, previous) {
  let auditSequence = previous?.auditSequence ?? 0;
  let eventKey = previous?.eventKey ?? null;
  for (const item of items) {
    if (item.ingest?.source === 'audit') auditSequence = Math.max(auditSequence, item.ingest.sequence);
    if (item.ingest?.source === 'event' && (!eventKey || compareKeys(item.ingest.key, eventKey) > 0)) eventKey = item.ingest.key;
  }
  return encodeActivityCursor({ auditSequence, eventKey });
}

function isNewerThanCursor(item, cursor) {
  if (item.ingest?.source === 'audit') return item.ingest.sequence > cursor.auditSequence;
  if (item.ingest?.source === 'event') return !cursor.eventKey || compareKeys(item.ingest.key, cursor.eventKey) > 0;
  return false;
}

function mergeByIngestion(audits, events, limit) {
  const out = [];
  let a = 0;
  let e = 0;
  while (out.length < limit && (a < audits.length || e < events.length)) {
    const takeAudit = e >= events.length
      || (a < audits.length && String(audits[a].at ?? '').localeCompare(String(events[e].at ?? '')) <= 0);
    out.push(takeAudit ? audits[a++] : events[e++]);
  }
  return out;
}

export function paginateActivity(items, { after = null, limit = 200 } = {}) {
  const bounded = Math.max(1, Math.min(500, Number(limit) || 200));
  const cursor = after ? decodeActivityCursor(after) : null;
  if (!after || (!cursor && !items.some((item) => item.id === after))) {
    const page = items.slice(-bounded);
    return { items: page.map(stripIngest), cursor: cursorAfter(items, null) };
  }
  if (!cursor) {
    const index = items.findIndex((item) => item.id === after);
    const page = items.slice(index + 1).slice(-bounded);
    return { items: page.map(stripIngest), cursor: cursorAfter(items, null) };
  }
  const fresh = items.filter((item) => isNewerThanCursor(item, cursor));
  const audits = fresh.filter((item) => item.ingest?.source === 'audit').sort((l, r) => l.ingest.sequence - r.ingest.sequence);
  const events = fresh.filter((item) => item.ingest?.source === 'event').sort((l, r) => compareKeys(l.ingest.key, r.ingest.key));
  const selected = new Set(mergeByIngestion(audits, events, bounded));
  const page = items.filter((item) => selected.has(item));
  return { items: page.map(stripIngest), cursor: cursorAfter(page, cursor) };
}

export function buildActivityItems({ scan, steps = [], auditEntries = [], runEvents = [] }) {
  const stepByRunId = new Map(steps.filter((step) => step.test_run_id).map((step) => [step.test_run_id, step]));
  const stepById = new Map(steps.map((step) => [step.id, step]));
  const items = [];
  const orderOf = new Map();
  for (const entry of auditEntries) {
    const metadata = entry.metadata ?? {};
    const step = stepById.get(metadata.step_id) ?? stepByRunId.get(entry.resource_type === 'test_run' ? entry.resource_id : metadata.test_run_id) ?? null;
    const rank = ACTIVITY_OPENER_ACTIONS.has(entry.action) ? 0 : 2;
    orderOf.set(entry.id ?? `${entry.sequence ?? ''}:${entry.action}`, [rank, Number.isFinite(entry.sequence) ? entry.sequence : items.length]);
    items.push({
      id: entry.id ?? `${entry.sequence ?? ''}:${entry.action}`,
      ingest: { source: 'audit', sequence: Number.isFinite(entry.sequence) ? entry.sequence : 0 },
      at: entry.timestamp ?? entry.created_at ?? null,
      kind: entry.resource_type === 'validation_scan' ? 'scan' : 'run',
      action: entry.action,
      summary: describeAuditAction(entry.action, metadata),
      step_id: step?.id ?? metadata.step_id ?? null,
      check_id: metadata.check_id ?? step?.check_id ?? null,
      test_run_id: entry.resource_type === 'test_run' ? entry.resource_id : (metadata.test_run_id ?? step?.test_run_id ?? null),
      actor_role: entry.actor_role ?? null,
      metadata: allowlistedMetadata(metadata),
    });
  }
  let eventOrder = 0;
  for (const event of runEvents) {
    if (event.signal_type === 'probe_activity' && event.producer_kind !== 'signed_probe') continue;
    const step = stepByRunId.get(event.test_run_id) ?? null;
    eventOrder += 1;
    orderOf.set(event.id, [1, eventOrder]);
    items.push({
      id: event.id,
      ingest: { source: 'event', key: eventIngestKey(event, eventOrder) },
      at: event.timestamp ?? null,
      kind: 'event',
      action: event.signal_type,
      summary: describeEvent(event),
      step_id: step?.id ?? null,
      check_id: event.check_id ?? step?.check_id ?? null,
      test_run_id: event.test_run_id ?? null,
      actor_role: null,
      metadata: {
        external_result: event.external_result ?? event.metadata?.external_result ?? undefined,
        status_code: event.metadata?.status_code ?? event.metadata?.response_status ?? undefined,
        requests_sent: event.metadata?.safety_attestation?.requests_sent ?? undefined,
        producer_kind: event.producer_kind ?? undefined,
        ...(event.signal_type === 'probe_activity' && event.producer_kind === 'signed_probe' ? {
          activity: event.metadata?.activity, vector_family: event.metadata?.vector_family,
          probe_kind: event.metadata?.probe_kind, marker_class: event.metadata?.marker_class,
        } : {}),
      },
    });
  }
  const compareOrder = (left, right) => {
    const [leftRank, leftSeq] = orderOf.get(left.id) ?? [1, 0];
    const [rightRank, rightSeq] = orderOf.get(right.id) ?? [1, 0];
    return leftRank - rightRank || leftSeq - rightSeq;
  };
  items.sort((left, right) => String(left.at ?? '').localeCompare(String(right.at ?? ''))
    || compareOrder(left, right)
    || String(left.id).localeCompare(String(right.id)));
  return items.map((item) => ({ ...item, scan_id: scan?.id ?? null }));
}
