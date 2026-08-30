import { createHash } from 'node:crypto';

export const POLICY_CADENCES = Object.freeze(['manual', 'daily', 'weekly', 'monthly']);

const CADENCES = new Set(POLICY_CADENCES);
const EXPECTED_VERDICTS = new Set(['pass', 'warn', 'fail', 'manual_review']);
const POLICY_STATES = new Set(['active', 'paused']);
const DAY_INDEX = new Map([
  ['sun', 0], ['sunday', 0],
  ['mon', 1], ['monday', 1],
  ['tue', 2], ['tues', 2], ['tuesday', 2],
  ['wed', 3], ['wednesday', 3],
  ['thu', 4], ['thur', 4], ['thurs', 4], ['thursday', 4],
  ['fri', 5], ['friday', 5],
  ['sat', 6], ['saturday', 6],
]);
const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const TIME_RE = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

export class PolicyValidationError extends Error {
  constructor(field, message, code = 'invalid_test_policy') {
    super(message);
    this.name = 'PolicyValidationError';
    this.code = code;
    this.status = 400;
    this.field = field;
  }

  toResponse() {
    return { error: this.code, status: this.status, field: this.field, message: this.message };
  }
}

export function normalizePolicyTimezone(value, field = 'timezone') {
  const timezone = String(value ?? 'UTC').trim() || 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(new Date(0));
  } catch {
    throw new PolicyValidationError(field, `Unknown IANA timezone: ${timezone}`);
  }
  return timezone;
}

function normalizeCadence(value) {
  const cadence = String(value ?? 'manual').trim().toLowerCase();
  if (!CADENCES.has(cadence)) throw new PolicyValidationError('cadence', `Unsupported policy cadence: ${cadence || '(empty)'}`);
  return cadence;
}

function normalizeExpectedVerdict(value) {
  const verdict = String(value ?? 'pass').trim().toLowerCase();
  if (!EXPECTED_VERDICTS.has(verdict)) throw new PolicyValidationError('expected_verdict', `Unsupported expected verdict: ${verdict || '(empty)'}`);
  return verdict;
}

function normalizeState(value) {
  const state = String(value ?? 'active').trim().toLowerCase();
  if (!POLICY_STATES.has(state)) throw new PolicyValidationError('state', `Unsupported policy state: ${state || '(empty)'}`);
  return state;
}

function normalizeBoolean(value, field, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new PolicyValidationError(field, `${field} must be a boolean.`);
  return value;
}

function normalizeEventTrigger(value) {
  if (value != null) {
    throw new PolicyValidationError('event_trigger', 'event_trigger is unavailable because no durable event consumer is configured.');
  }
  return null;
}

export function normalizeSafeWindows(value, { timezone = 'UTC' } = {}) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new PolicyValidationError('safe_windows', 'safe_windows must be an array.');
  if (value.length > 14) throw new PolicyValidationError('safe_windows', 'A policy may define at most 14 safe windows.');
  return value.map((window, index) => {
    if (!window || typeof window !== 'object' || Array.isArray(window)) {
      throw new PolicyValidationError(`safe_windows[${index}]`, 'Each safe window must be an object.');
    }
    const dayIndex = DAY_INDEX.get(String(window.day ?? '').trim().toLowerCase());
    const start = String(window.start ?? '').trim();
    const end = String(window.end ?? '').trim();
    if (dayIndex === undefined) throw new PolicyValidationError(`safe_windows[${index}].day`, 'Safe window day must be Mon through Sun.');
    if (!TIME_RE.test(start)) throw new PolicyValidationError(`safe_windows[${index}].start`, 'Safe window start must use 24-hour HH:MM.');
    if (!TIME_RE.test(end)) throw new PolicyValidationError(`safe_windows[${index}].end`, 'Safe window end must use 24-hour HH:MM.');
    if (start >= end) throw new PolicyValidationError(`safe_windows[${index}].end`, 'Safe window end must be later than its start on the same day.');
    return {
      day: DAY_LABELS[dayIndex],
      start,
      end,
      timezone: normalizePolicyTimezone(window.timezone ?? timezone, `safe_windows[${index}].timezone`),
    };
  });
}

export function normalizePolicyInput(input, { current = null, maxConcurrency = 1 } = {}) {
  const body = input && typeof input === 'object' ? input : {};
  const cadence = normalizeCadence(body.cadence ?? current?.cadence ?? 'manual');
  const timezoneHint = body.timezone
    ?? body.safe_windows?.[0]?.timezone
    ?? current?.timezone
    ?? current?.safe_windows?.[0]?.timezone
    ?? 'UTC';
  const timezone = normalizePolicyTimezone(timezoneHint);
  const safeWindows = body.safe_windows === undefined
    ? normalizeSafeWindows(current?.safe_windows ?? [], { timezone })
    : normalizeSafeWindows(body.safe_windows, { timezone });
  const state = normalizeState(body.state ?? current?.state ?? 'active');
  const enabled = normalizeBoolean(body.enabled, 'enabled', current?.enabled ?? state === 'active');
  const rawMax = body.max_concurrent_runs ?? current?.max_concurrent_runs ?? 1;
  const maxConcurrentRuns = Number(rawMax);
  if (!Number.isSafeInteger(maxConcurrentRuns) || maxConcurrentRuns < 1 || maxConcurrentRuns > maxConcurrency) {
    throw new PolicyValidationError('max_concurrent_runs', `max_concurrent_runs must be an integer between 1 and ${maxConcurrency}.`);
  }
  const eventTriggerInput = body.event_trigger !== undefined ? body.event_trigger : current?.event_trigger;
  const eventTrigger = normalizeEventTrigger(eventTriggerInput);
  return {
    cadence,
    expected_verdict: normalizeExpectedVerdict(body.expected_verdict ?? current?.expected_verdict ?? 'pass'),
    safe_windows: safeWindows,
    timezone,
    event_trigger: eventTrigger,
    state,
    enabled,
    max_concurrent_runs: maxConcurrentRuns,
  };
}

function zonedParts(date, timezone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23', weekday: 'short',
  }).formatToParts(date);
  const map = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return {
    year: Number(map.year), month: Number(map.month), day: Number(map.day),
    hour: Number(map.hour), minute: Number(map.minute), second: Number(map.second),
    weekday: DAY_INDEX.get(map.weekday.toLowerCase()),
  };
}

function zonedDateToUtc(parts, timezone) {
  const desired = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour ?? 0, parts.minute ?? 0, parts.second ?? 0);
  let candidate = desired;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const actual = zonedParts(new Date(candidate), timezone);
    const represented = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, actual.second);
    const adjustment = desired - represented;
    candidate += adjustment;
    if (adjustment === 0) break;
  }
  return new Date(candidate);
}

function addLocalDays(parts, days) {
  const date = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days, parts.hour, parts.minute, parts.second));
  return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate(), hour: parts.hour, minute: parts.minute, second: parts.second };
}

function cadenceFloor(policy, from, initial) {
  const timezone = policy.timezone ?? 'UTC';
  const parts = zonedParts(from, timezone);
  if (initial) return new Date(from.getTime() + 60_000);
  if (policy.cadence === 'daily') return zonedDateToUtc(addLocalDays(parts, 1), timezone);
  if (policy.cadence === 'weekly') return zonedDateToUtc(addLocalDays(parts, 7), timezone);
  if (policy.cadence === 'monthly') {
    const lastDay = new Date(Date.UTC(parts.year, parts.month + 1, 0)).getUTCDate();
    return zonedDateToUtc({ ...parts, month: parts.month + 1, day: Math.min(parts.day, lastDay) }, timezone);
  }
  return null;
}

function alignToSafeWindow(policy, floor) {
  if (!policy.safe_windows?.length) return floor;
  let earliest = null;
  for (const window of policy.safe_windows) {
    const timezone = window.timezone ?? policy.timezone ?? 'UTC';
    const local = zonedParts(floor, timezone);
    const desiredDay = DAY_INDEX.get(String(window.day).toLowerCase());
    const [hour, minute] = window.start.split(':').map(Number);
    for (let offset = 0; offset <= 370; offset += 1) {
      const dateParts = addLocalDays({ ...local, hour, minute, second: 0 }, offset);
      const candidate = zonedDateToUtc(dateParts, timezone);
      const resolved = zonedParts(candidate, timezone);
      const exactWallClock = resolved.year === dateParts.year
        && resolved.month === dateParts.month
        && resolved.day === dateParts.day
        && resolved.hour === dateParts.hour
        && resolved.minute === dateParts.minute;
      if (!exactWallClock || resolved.weekday !== desiredDay || candidate < floor) continue;
      if (!earliest || candidate < earliest) earliest = candidate;
      break;
    }
  }
  return earliest;
}

export function isWithinPolicySafeWindow(policy, now = Date.now()) {
  const windows = policy?.safe_windows ?? [];
  if (!windows.length) return true;
  const instant = now instanceof Date ? now : new Date(now);
  if (Number.isNaN(instant.getTime())) return false;
  return windows.some((window) => {
    const timezone = window.timezone ?? policy.timezone ?? 'UTC';
    const parts = zonedParts(instant, timezone);
    const expectedDay = DAY_INDEX.get(String(window.day ?? '').toLowerCase());
    if (expectedDay === undefined || parts.weekday !== expectedDay) return false;
    const [startHour, startMinute] = String(window.start ?? '').split(':').map(Number);
    const [endHour, endMinute] = String(window.end ?? '').split(':').map(Number);
    if (![startHour, startMinute, endHour, endMinute].every(Number.isInteger)) return false;
    const currentMinute = parts.hour * 60 + parts.minute;
    return currentMinute >= startHour * 60 + startMinute
      && currentMinute <= endHour * 60 + endMinute;
  });
}

export function nextPolicyRunAt(policy, { from = new Date(), initial = false } = {}) {
  const source = from instanceof Date ? from : new Date(from);
  if (Number.isNaN(source.getTime())) throw new PolicyValidationError('next_run_at', 'Schedule reference time must be a valid timestamp.');
  if (!policy.enabled || policy.state !== 'active' || ['manual', 'event_driven'].includes(policy.cadence)) return null;
  const floor = cadenceFloor(policy, source, initial);
  return alignToSafeWindow(policy, floor)?.toISOString() ?? null;
}

export function policyDispatchIdempotencyKey(tenantId, policyId, scheduledFor) {
  const scheduled = new Date(scheduledFor);
  if (Number.isNaN(scheduled.getTime())) throw new PolicyValidationError('scheduled_for', 'Dispatch schedule must be a valid timestamp.');
  return createHash('sha256').update(`${tenantId}\u0000${policyId}\u0000${scheduled.toISOString()}`).digest('hex');
}

export function policyValidationResponse(error) {
  if (error instanceof PolicyValidationError) return error.toResponse();
  throw error;
}
