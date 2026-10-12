const MAX_DATE_MS = 8_640_000_000_000_000;
const MAX_DATE_SECONDS = BigInt(MAX_DATE_MS / 1000);

/** Parse an explicit-zone ISO clock without discarding sub-millisecond precision. */
export function ownershipTransitionInstant(value) {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) return null;
    value = value.toISOString();
  }
  if (typeof value !== 'string') return null;
  const match = /^(\d{4}|[+-]\d{6})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second, rawFraction = '', zone] = match;
  const [y, mo, d, h, mi, s] = [year, month, day, hour, minute, second].map(Number);
  const leapYear = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth[mo - 1] || h > 23 || mi > 59 || s > 59) return null;
  if (zone.toUpperCase() !== 'Z'
    && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) return null;
  // Parse only whole seconds, then compare the untouched decimal fraction separately.
  // Keeping the explicit offset here also handles Date-range boundaries in local time.
  const wholeSecondMs = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone.toUpperCase()}`);
  if (!Number.isFinite(wholeSecondMs)) return null;
  const seconds = BigInt(wholeSecondMs / 1000);
  const fraction = rawFraction.replace(/0+$/, '');
  if (seconds < -MAX_DATE_SECONDS || seconds > MAX_DATE_SECONDS
    || (seconds === MAX_DATE_SECONDS && fraction)) return null;
  return { seconds, fraction };
}

export function compareOwnershipInstants(left, right) {
  if (left.seconds !== right.seconds) return left.seconds < right.seconds ? -1 : 1;
  const width = Math.max(left.fraction.length, right.fraction.length);
  const a = left.fraction.padEnd(width, '0');
  const b = right.fraction.padEnd(width, '0');
  return a === b ? 0 : a < b ? -1 : 1;
}

function invalidTransition() {
  const error = new Error('Ownership chronology cannot safely advance.');
  error.code = 'ownership_transition_invalid';
  error.status = 409;
  return error;
}

/** Allocate before success audits; callers synchronously append before another allocation. */
export function allocateOwnershipTransitionAt(store, tenantId, targetId, nowMs = Date.now()) {
  if (!Number.isSafeInteger(nowMs) || Math.abs(nowMs) > MAX_DATE_MS) throw invalidTransition();
  let latest = null;
  for (const row of store.targetVerifications ?? []) {
    if (row.tenant_id !== tenantId || row.target_id !== targetId) continue;
    const instant = ownershipTransitionInstant(row.transitioned_at);
    if (!instant) throw invalidTransition();
    if (!latest || compareOwnershipInstants(instant, latest) > 0) latest = instant;
  }
  let nextMs = BigInt(nowMs);
  if (latest) {
    // Fractional seconds are nonnegative even before epoch: truncate the fraction,
    // then advance one whole millisecond to be strictly above the exact instant.
    const afterLatest = latest.seconds * 1000n + BigInt(latest.fraction.padEnd(3, '0').slice(0, 3) || '0') + 1n;
    if (afterLatest > nextMs) nextMs = afterLatest;
  }
  if (nextMs > BigInt(MAX_DATE_MS) || nextMs < -BigInt(MAX_DATE_MS)) throw invalidTransition();
  return new Date(Number(nextMs)).toISOString();
}
