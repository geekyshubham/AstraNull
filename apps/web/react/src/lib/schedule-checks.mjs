/**
 * Schedule check picker model. Every catalog check is listed; a check the server would refuse
 * for this tenant (isCustomerRunnable in src/contracts/checks.mjs) stays visible but disabled.
 */
import { checkPresentation } from './check-presentation.mjs';
import { CHECK_CATEGORIES, MISC_CATEGORY_ID, checkCategoryId } from './vector-library.mjs';

export const SOC_GOVERNED_LABEL = 'SOC-governed · request through SOC';
export const SOC_GOVERNED_REASON = 'This check needs a SOC-approved high-scale request; it cannot run from a schedule.';

function text(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

/** Mirrors the server: the demo account runs everything; others cannot schedule SOC-gated checks. */
export function isScheduleCheckSelectable(check, allChecksRunnable = false) {
  if (!check || typeof check !== 'object') return false;
  if (allChecksRunnable) return true;
  if (text(check.risk_class) === 'soc_gated') return false;
  if (check.safety_constraints && check.safety_constraints.customer_runnable === false) return false;
  return true;
}

export function scheduleCheckEntries(checks, { allChecksRunnable = false } = {}) {
  const entries = (Array.isArray(checks) ? checks : [])
    .filter((check) => check && typeof check === 'object' && text(check.check_id ?? check.id))
    .map((check) => {
      const id = text(check.check_id ?? check.id);
      const selectable = isScheduleCheckSelectable(check, allChecksRunnable);
      return {
        id,
        name: text(checkPresentation(check).name) || text(check.name) || id,
        category: checkCategoryId(check),
        selectable,
        reason: selectable ? '' : SOC_GOVERNED_REASON,
        check,
      };
    });
  return entries.sort((left, right) => Number(right.selectable) - Number(left.selectable) || left.name.localeCompare(right.name));
}

export function filterScheduleCheckEntries(entries, { query = '', category = '', keepId = '' } = {}) {
  const needle = text(query).toLowerCase();
  return (Array.isArray(entries) ? entries : []).filter((entry) => {
    if (keepId && entry.id === keepId) return true;
    if (category && entry.category !== category) return false;
    return !needle || `${entry.name} ${entry.id}`.toLowerCase().includes(needle);
  });
}

export function scheduleCheckCategoryCounts(entries) {
  const counts = { '': 0 };
  for (const entry of Array.isArray(entries) ? entries : []) {
    counts[''] += 1;
    counts[entry.category] = (counts[entry.category] ?? 0) + 1;
  }
  return [
    { id: '', label: 'All', count: counts[''] },
    ...CHECK_CATEGORIES.map((category) => ({ id: category.id, label: category.label, count: counts[category.id] ?? 0 })),
    { id: MISC_CATEGORY_ID, label: 'Other', count: counts[MISC_CATEGORY_ID] ?? 0 },
  ].filter((entry) => entry.id === '' || entry.count > 0);
}
