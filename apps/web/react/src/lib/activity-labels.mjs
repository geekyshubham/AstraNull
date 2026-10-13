import { plainCodeLabel } from './plain-language.mjs';

/** Dotted identifiers (check IDs, scenario IDs) are shown verbatim; plain snake_case codes are humanised. */
export function activityValueLabel(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return { text: '', code: false };
  if (raw.includes('.')) return { text: raw, code: true };
  return { text: plainCodeLabel(raw, ''), code: false };
}

/** Recorded request count only; a missing count is never shown as zero. */
export function activityRequestsSentLabel(count) {
  return count === null || count === undefined || count === '' || !Number.isFinite(Number(count))
    ? 'Requests sent: not recorded'
    : `${Number(count)} requests sent (recorded)`;
}

/** The authorized ceiling, kept separate from what was sent. */
export function activityRequestLimitLabel(max) {
  return max === null || max === undefined || !Number.isFinite(Number(max)) ? '' : `Limit: up to ${Number(max)} requests`;
}
