/**
 * Target-group label resolution for the finding detail rule-wide asset table.
 *
 * Plain ESM so the cold/warm/failed states are directly testable with node:test
 * (tests/unit/finding-group-labels.test.mjs). Every state keeps the recorded group ID
 * visible; a failed target-group load is reported explicitly instead of silently
 * degrading to an opaque ID.
 */

function readString(item, keys) {
  if (!item || typeof item !== 'object') return '';
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return '';
}

/** Map of target-group ID -> recorded name (groups without a recorded name are omitted). */
export function buildTargetGroupNameMap(targetGroups) {
  const names = new Map();
  for (const group of Array.isArray(targetGroups) ? targetGroups : []) {
    const id = readString(group, ['id', 'target_group_id']);
    const name = readString(group, ['name', 'display_name']);
    if (id && name) names.set(id, name);
  }
  return names;
}

/**
 * Resolve how one finding's target group should be labelled.
 *
 * - `ungrouped`: the finding records no target group.
 * - `named`: the recorded group name is available.
 * - `unavailable`: the target-group dataset failed to load, so names cannot be shown.
 * - `unrecorded`: groups loaded, but this ID has no recorded name (e.g. deleted group).
 */
export function resolveTargetGroupLabel(groupId, { names, loadError } = {}) {
  const id = typeof groupId === 'string' ? groupId.trim() : '';
  if (!id) return { state: 'ungrouped', id: '', name: '' };
  const name = names instanceof Map ? names.get(id) ?? '' : '';
  if (name) return { state: 'named', id, name };
  if (loadError) return { state: 'unavailable', id, name: '' };
  return { state: 'unrecorded', id, name: '' };
}
