/** Mirrors src/contracts/validationScanManagement.mjs; parity is asserted by tests/unit/validation-scan-ui.test.mjs. */
export const SCAN_STATUSES = Object.freeze(['scheduled', 'pending', 'running', 'completed', 'denied', 'cancelled']);
export const ACTIVE_SCAN_STATUSES = Object.freeze(['pending', 'running']);
export const CANCELLABLE_SCAN_STATUSES = Object.freeze(['scheduled', 'pending', 'running']);
export const TERMINAL_SCAN_STATUSES = Object.freeze(['completed', 'denied', 'cancelled']);
export const STEP_STATUSES = Object.freeze([
  'pending', 'deferred', 'starting', 'running', 'collecting', 'verdicted', 'denied', 'skipped', 'cancelled',
]);
export const ACTIVE_STEP_STATUSES = Object.freeze(['starting', 'running', 'collecting']);
export const SCAN_RECURRENCE_CADENCES = Object.freeze(['daily', 'weekly', 'monthly']);
export const MAX_SCAN_CHECKS = 50;
export const MIN_SCHEDULE_LEAD_MS = 60_000;
export const MAX_SCAN_NAME_LENGTH = 120;
export const SCAN_POLL_BASE_MS = 2500;
export const SCAN_POLL_MAX_MS = 10_000;
export const SCAN_POLL_SCHEDULED_MS = 15_000;

export const SCAN_ERROR_COPY = Object.freeze({
  soc_gated_check: 'One selected check requires SOC governance and cannot run as a customer scan. Remove it and try again.',
  check_requires_additional_input: 'One selected check needs additional customer setup before it can run. Remove it and try again.',
  unknown_check: 'One selected check is not in the current catalog. Refresh the catalog and try again.',
  target_kind_not_supported: 'One selected check does not support the kind of the exact target chosen.',
  scan_has_no_runnable_steps: 'None of the selected checks apply to the targets in this scope, so no step could be planned.',
  scan_too_large: 'This scan plans too many check and target steps. Narrow the scope or select fewer checks.',
  invalid_validation_scan: 'The scan request was rejected. Check the values entered and try again.',
  target_group_not_found: 'That target group no longer exists or is archived. Refresh and choose another.',
  target_not_found: 'That exact target no longer exists in the selected group. Refresh and choose another.',
  concurrent_scan_blocked: 'A scan or run is already active for this target group. Wait for it to finish or stop it before starting another.',
  scan_not_editable: 'Only scans that are still scheduled can be edited. Refresh to see the current status.',
  not_cancellable: 'This scan has already finished and cannot be stopped.',
});

function text(value) {
  return String(value ?? '').trim();
}

function humanizeCode(value) {
  const words = text(value).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!words) return '';
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

export const GROUP_SCAN_LIST_LIMIT = 200;

export function validationScansPathForGroup(targetGroupId, limit = GROUP_SCAN_LIST_LIMIT) {
  const params = new URLSearchParams({ target_group_id: String(targetGroupId ?? ''), limit: String(limit) });
  return `/v1/validation-scans?${params.toString()}`;
}

export function humanizeReason(code) {
  const raw = text(code);
  if (!raw) return '';
  const [head, detail] = raw.split(':');
  const headCopy = humanizeCode(head);
  return detail ? `${headCopy} (${humanizeCode(detail).toLowerCase()})` : headCopy;
}

export function scanErrorMessage(payload, fallback = 'The scan request could not be completed.') {
  const body = payload && typeof payload === 'object' ? payload : {};
  const code = text(body.error);
  const known = SCAN_ERROR_COPY[code];
  const detail = [];
  if (body.check_id) detail.push(`Check: ${text(body.check_id)}`);
  if (body.field && body.message) detail.push(text(body.message));
  if (Array.isArray(body.excluded) && body.excluded.length) {
    detail.push(`${body.excluded.length} incompatible check/target pair${body.excluded.length === 1 ? '' : 's'}.`);
  }
  if (known) return [known, ...detail].join(' ');
  if (body.message) return [text(body.message), ...detail.filter((entry) => entry !== text(body.message))].join(' ');
  if (code) return [`${humanizeCode(code)}.`, ...detail].join(' ');
  return fallback;
}

export function isScanActive(scan) {
  return ACTIVE_SCAN_STATUSES.includes(text(scan?.status));
}

export function isScanCancellable(scan) {
  return CANCELLABLE_SCAN_STATUSES.includes(text(scan?.status));
}

export function isScanEditable(scan) {
  return text(scan?.status) === 'scheduled';
}

export function isScanTerminal(scan) {
  return TERMINAL_SCAN_STATUSES.includes(text(scan?.status));
}

export function isScanScheduled(scan) {
  return text(scan?.status) === 'scheduled';
}

export function scanStatusTone(status) {
  const key = text(status).toLowerCase();
  if (key === 'completed') return 'success';
  if (key === 'running' || key === 'pending') return 'info';
  if (key === 'scheduled') return 'muted';
  if (key === 'denied' || key === 'cancelled') return 'danger';
  return 'warn';
}

export function stepStatusTone(status) {
  const key = text(status).toLowerCase();
  if (key === 'verdicted') return 'success';
  if (ACTIVE_STEP_STATUSES.includes(key)) return 'info';
  if (key === 'pending') return 'muted';
  if (key === 'deferred') return 'warn';
  if (key === 'denied' || key === 'cancelled') return 'danger';
  if (key === 'skipped') return 'muted';
  return 'warn';
}

export function scanStatusLabel(status) {
  return humanizeCode(status) || 'Unknown';
}

export function stepStatusLabel(status) {
  return humanizeCode(status) || 'Unknown';
}

export function isStepActive(step) {
  return ACTIVE_STEP_STATUSES.includes(text(step?.status));
}

export function scanProgressPercent(summary) {
  const total = Number(summary?.total);
  const completed = Number(summary?.completed);
  if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(completed)) return 0;
  return Math.max(0, Math.min(100, Math.round((completed / total) * 100)));
}

export function formatStepRequest(request) {
  if (!request || typeof request !== 'object') return 'Not recorded';
  const parts = [];
  if (request.kind) parts.push(humanizeCode(request.kind));
  const line = [request.method ? text(request.method).toUpperCase() : '', text(request.path)].filter(Boolean).join(' ');
  if (line) parts.push(line);
  if (request.protocol) parts.push(text(request.protocol).toUpperCase());
  if (Number.isFinite(Number(request.max_requests)) && request.max_requests !== null) {
    parts.push(`max ${Number(request.max_requests)} request${Number(request.max_requests) === 1 ? '' : 's'}`);
  }
  if (Number.isFinite(Number(request.timeout_ms)) && request.timeout_ms !== null) parts.push(`${Number(request.timeout_ms)} ms timeout`);
  return parts.length ? parts.join(' · ') : 'Not recorded';
}

export function formatStepResponse(response) {
  if (!response || typeof response !== 'object') return 'Awaiting response';
  const parts = [];
  if (response.external_result) parts.push(humanizeCode(response.external_result));
  if (response.status_code !== null && response.status_code !== undefined && text(response.status_code)) {
    parts.push(`HTTP ${text(response.status_code)}`);
  }
  return parts.length ? parts.join(' · ') : 'Awaiting response';
}

export function formatRequestsSent(step) {
  if (!step || typeof step !== 'object') return '—';
  if (step.requests_inline) return 'inline, no network';
  const count = Number(step.requests_sent);
  if (step.requests_simulated) return `${Number.isFinite(count) ? count : 0} (simulated, no live traffic)`;
  if (step.requests_sent === null || step.requests_sent === undefined || !Number.isFinite(count)) return '—';
  return String(count);
}

export function mergeActivity(existing, incoming) {
  const byId = new Map();
  for (const item of [...(Array.isArray(existing) ? existing : []), ...(Array.isArray(incoming) ? incoming : [])]) {
    if (!item || item.id === undefined || item.id === null) continue;
    byId.set(String(item.id), item);
  }
  return [...byId.values()].sort((left, right) => (
    text(left.at).localeCompare(text(right.at)) || String(left.id).localeCompare(String(right.id))
  ));
}

export function nextPollDelay({ status, errorCount = 0 } = {}) {
  const errors = Math.max(0, Number(errorCount) || 0);
  if (errors > 0) return Math.min(SCAN_POLL_MAX_MS, SCAN_POLL_BASE_MS * 2 ** errors);
  if (text(status) === 'scheduled') return SCAN_POLL_SCHEDULED_MS;
  if (ACTIVE_SCAN_STATUSES.includes(text(status))) return SCAN_POLL_BASE_MS;
  return null;
}

export function scopeLabel(scan) {
  if (!scan) return 'Scope not recorded';
  const group = text(scan.target_group?.name) || text(scan.target_group_id) || 'target group';
  if (scan.target_id) {
    const target = text(scan.target?.value) || text(scan.target_id);
    return `Exact target ${target} in ${group}`;
  }
  return `Whole group ${group}`;
}

export function recurrenceLabel(recurrence) {
  if (!recurrence) return 'One-time';
  const cadence = text(typeof recurrence === 'string' ? recurrence : recurrence.cadence);
  if (!cadence || cadence === 'none') return 'One-time';
  const zone = typeof recurrence === 'object' ? text(recurrence.timezone) : '';
  return zone ? `${humanizeCode(cadence)} (${zone})` : humanizeCode(cadence);
}

export function scanDisplayName(scan) {
  return text(scan?.name) || text(scan?.id) || 'Validation scan';
}

function pad(value) {
  return String(value).padStart(2, '0');
}

export function isoToLocalDatetime(iso) {
  const date = new Date(text(iso));
  if (!text(iso) || Number.isNaN(date.getTime())) return '';
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function localDatetimeToIso(value) {
  const raw = text(value);
  if (!raw) return '';
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

export function minScheduleLocalValue(now = Date.now()) {
  const base = now instanceof Date ? now.getTime() : Number(now);
  return isoToLocalDatetime(new Date(base + MIN_SCHEDULE_LEAD_MS).toISOString());
}

export function emptyScanForm(overrides = {}) {
  return {
    targetGroupId: '',
    scope: 'group',
    targetId: '',
    checkIds: [],
    name: '',
    schedule: 'now',
    scheduledForLocal: '',
    recurrence: 'none',
    timezone: '',
    ...overrides,
  };
}

export function scanFormFromScan(scan, mode = 'edit') {
  const recurrence = scan?.recurrence && typeof scan.recurrence === 'object' ? scan.recurrence : null;
  return emptyScanForm({
    targetGroupId: text(scan?.target_group_id),
    scope: scan?.target_id ? 'target' : 'group',
    targetId: text(scan?.target_id),
    checkIds: Array.isArray(scan?.check_ids) ? scan.check_ids.map(text).filter(Boolean) : [],
    name: text(scan?.name),
    schedule: 'later',
    scheduledForLocal: mode === 'edit' ? isoToLocalDatetime(scan?.scheduled_for) : '',
    recurrence: recurrence ? text(recurrence.cadence) || 'none' : 'none',
    timezone: recurrence ? text(recurrence.timezone) : '',
  });
}

export function validateScanForm(form, { now = Date.now() } = {}) {
  const errors = {};
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  if (!text(form?.targetGroupId)) errors.target_group_id = 'Select a target group.';
  if (form?.scope === 'target' && !text(form?.targetId)) errors.target_id = 'Select an exact target or switch to the whole group.';
  const ids = [...new Set((Array.isArray(form?.checkIds) ? form.checkIds : []).map(text).filter(Boolean))];
  if (ids.length === 0) errors.check_ids = 'Select at least one check.';
  if (ids.length > MAX_SCAN_CHECKS) errors.check_ids = `Select at most ${MAX_SCAN_CHECKS} checks per scan.`;
  if (text(form?.name).length > MAX_SCAN_NAME_LENGTH) errors.name = `Name must be at most ${MAX_SCAN_NAME_LENGTH} characters.`;
  if (form?.schedule === 'later') {
    const iso = localDatetimeToIso(form?.scheduledForLocal);
    if (!iso) errors.scheduled_for = 'Choose a valid date and time.';
    else if (new Date(iso).getTime() < nowMs + MIN_SCHEDULE_LEAD_MS) errors.scheduled_for = 'Schedule at least one minute in the future.';
    const cadence = text(form?.recurrence);
    if (cadence && cadence !== 'none' && !SCAN_RECURRENCE_CADENCES.includes(cadence)) errors.recurrence = 'Choose a supported recurrence.';
  } else if (text(form?.recurrence) && text(form?.recurrence) !== 'none') {
    errors.recurrence = 'A recurring scan needs a scheduled first occurrence.';
  }
  return { ok: Object.keys(errors).length === 0, errors };
}

export function buildScanPayload(form) {
  const payload = {
    target_group_id: text(form?.targetGroupId),
    check_ids: [...new Set((Array.isArray(form?.checkIds) ? form.checkIds : []).map(text).filter(Boolean))],
  };
  if (form?.scope === 'target' && text(form?.targetId)) payload.target_id = text(form.targetId);
  if (text(form?.name)) payload.name = text(form.name);
  if (form?.schedule === 'later') {
    payload.scheduled_for = localDatetimeToIso(form?.scheduledForLocal);
    const cadence = text(form?.recurrence);
    if (cadence && cadence !== 'none') {
      payload.recurrence = text(form?.timezone) ? { cadence, timezone: text(form.timezone) } : cadence;
    }
  }
  return payload;
}

export function buildScanPatch(scan, form) {
  const next = buildScanPayload(form);
  const patch = {};
  const currentTargetId = text(scan?.target_id) || null;
  const nextTargetId = next.target_id ?? null;
  if (currentTargetId !== nextTargetId) patch.target_id = nextTargetId;
  const currentChecks = Array.isArray(scan?.check_ids) ? scan.check_ids.map(text) : [];
  if (JSON.stringify(currentChecks) !== JSON.stringify(next.check_ids)) patch.check_ids = next.check_ids;
  const currentName = text(scan?.name) || null;
  const nextName = next.name ?? null;
  if (currentName !== nextName) patch.name = nextName;
  const currentScheduled = text(scan?.scheduled_for) || null;
  const nextScheduled = next.scheduled_for || null;
  if (currentScheduled !== nextScheduled) patch.scheduled_for = nextScheduled;
  const currentRecurrence = scan?.recurrence && typeof scan.recurrence === 'object' ? scan.recurrence : null;
  const nextRecurrence = next.recurrence ?? null;
  const currentCadence = currentRecurrence ? text(currentRecurrence.cadence) : null;
  const nextCadence = nextRecurrence ? (typeof nextRecurrence === 'string' ? nextRecurrence : text(nextRecurrence.cadence)) : null;
  const currentZone = currentRecurrence ? text(currentRecurrence.timezone) : '';
  const nextZone = nextRecurrence && typeof nextRecurrence === 'object' ? text(nextRecurrence.timezone) : '';
  if (currentCadence !== nextCadence || (nextZone && nextZone !== currentZone)) patch.recurrence = nextRecurrence ?? 'none';
  return patch;
}
