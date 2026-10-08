/** Resolve a declared target's existing execution policy on the server, never from a hostname. */
const TARGET_ID = /^[A-Za-z0-9_-]{1,160}$/;

export async function bindDeclaredTargetInput(ctx, input, targets, { allowMultiple = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'invalid_target_selection', status: 400 };
  // Existing scope inputs remain compatible; new clients send declared target IDs only.
  if (input.target_group_id && input.target_ids == null) return { input };
  if (input.target_ids == null && (input.target_id == null || input.target_id === '')) return { input };
  const raw = input.target_ids ?? [input.target_id];
  if (!Array.isArray(raw) || !raw.length || raw.length > 500 || raw.some((id) => typeof id !== 'string' || !TARGET_ID.test(id))) {
    return { error: 'invalid_target_selection', status: 400, field: 'target_ids' };
  }
  const ids = [...new Set(raw)];
  if ((!allowMultiple && ids.length !== 1) || (input.target_id && (ids.length !== 1 || ids[0] !== input.target_id))) {
    return { error: 'target_selection_conflict', status: 400 };
  }
  const selected = [];
  let rows;
  if (typeof targets?.getTarget !== 'function') {
    if (typeof targets?.listTargets !== 'function') return { error: 'target_selection_unavailable', status: 503 };
    rows = await targets.listTargets(ctx);
  }
  for (const id of ids) {
    const target = rows ? rows.find((row) => row.id === id) : await targets.getTarget(ctx, id);
    if (!target || target.tenant_id !== ctx.tenantId || target.deleted_at || target.archived_at) return { error: 'target_not_found', status: 404 };
    if (!target.target_group_id) return { error: 'target_execution_policy_unavailable', status: 503 };
    selected.push(target);
  }
  if (input.target_group_id && input.target_group_id !== selected[0].target_group_id) return { error: 'target_selection_conflict', status: 400 };
  return { input: { ...input, target_group_id: selected[0].target_group_id, target_id: ids.length === 1 ? ids[0] : null,
    ...(input.target_ids != null ? { target_ids: ids } : {}) }, target: selected[0], targets: selected };
}

/** Customer target projections omit obsolete selection identifiers without modifying storage. */
export function presentTargetSelection(value) {
  if (Array.isArray(value)) return value.map(presentTargetSelection);
  if (!value || typeof value !== 'object' || value instanceof Date) return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !['target_group_id', 'target_group_ids', 'target_group_name', 'target_group', 'target_groups', 'group_refs'].includes(key))
    .map(([key, item]) => [key, presentTargetSelection(item)]));
}
