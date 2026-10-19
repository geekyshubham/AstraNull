import { FINDING_STATUSES, FINDING_SEVERITY_CLASSES, findingsQuery } from './findings-query.mjs';

export const FILTER_QUESTION_MAX = 500;
export const ASSISTANT_FILTER_KEYS = Object.freeze(['q', 'status', 'severity', 'check_id', 'target_id', 'test_run_id']);
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

/** Reject the whole preview rather than silently dropping an unsupported field. Server authorizes IDs. */
export function sanitizeFindingFilterPreview(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  if (!keys.every((key) => ['filters', 'explanation'].includes(key))) return null;
  const filters = value.filters;
  if (!filters || typeof filters !== 'object' || Array.isArray(filters)) return null;
  const out = {};
  for (const [key, entry] of Object.entries(filters)) {
    if (!ASSISTANT_FILTER_KEYS.includes(key) || typeof entry !== 'string' || !entry || entry !== entry.trim() || CONTROL.test(entry)) return null;
    if (key === 'q' ? entry.length > 200 : key === 'status' ? !FINDING_STATUSES.includes(entry) : key === 'severity' ? !FINDING_SEVERITY_CLASSES.includes(entry) : !ID.test(entry)) return null;
    out[key] = entry;
  }
  if (typeof value.explanation !== 'string' || !value.explanation.trim() || value.explanation.length > 1000 || CONTROL.test(value.explanation)) return null;
  return { filters: out, explanation: value.explanation };
}

/** The exact existing server predicate; paging stays owned by the findings hooks. Never takes a prompt. */
export function assistantFindingQuery(preview, paging = {}) {
  const safe = sanitizeFindingFilterPreview(preview);
  return safe ? findingsQuery({ ...safe.filters, limit: paging.limit, page: paging.page }) : null;
}
