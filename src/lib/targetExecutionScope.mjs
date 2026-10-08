/** Exact declared-target scope for retained multi-target scan plans and legacy records. */
export function scanTargetIds(scan) {
  return [...new Set([
    ...(Array.isArray(scan?.plan_snapshot?.target_ids) ? scan.plan_snapshot.target_ids : []),
    ...(scan?.target_id ? [scan.target_id] : []),
    ...(Array.isArray(scan?.steps) ? scan.steps.map((step) => step.target_id) : []),
  ].filter((id) => typeof id === 'string' && id))];
}

export function scanIncludesTarget(scan, targetId, targetGroupId) {
  const ids = scanTargetIds(scan);
  return ids.length ? ids.includes(targetId) : scan?.target_group_id === targetGroupId;
}
