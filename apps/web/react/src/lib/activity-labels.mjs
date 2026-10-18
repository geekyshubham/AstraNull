import { plainCodeLabel } from './plain-language.mjs';

/** Dotted identifiers (check IDs, scenario IDs) are shown verbatim; plain snake_case codes are humanised. */
export function activityValueLabel(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return { text: '', code: false };
  if (raw.includes('.')) return { text: raw, code: true };
  return { text: plainCodeLabel(raw, ''), code: false };
}

/** Legacy requests_sent records attested logical operations, not completed HTTP requests. */
export function activityRequestsSentLabel(count) {
  return count === null || count === undefined || count === '' || !Number.isFinite(Number(count))
    ? 'Logical operations: not recorded'
    : `${Number(count)} logical operations (attested)`;
}

/** The authorized ceiling, kept separate from what was sent. */
export function activityRequestLimitLabel(max) {
  return max === null || max === undefined || !Number.isFinite(Number(max)) ? '' : `Signed probe allowance: up to ${Number(max)} logical attempts`;
}
