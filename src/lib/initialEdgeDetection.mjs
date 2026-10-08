export const INITIAL_EDGE_CHECK_ID = 'waf.fingerprint.safe';
export const INITIAL_EDGE_KINDS = Object.freeze(['fqdn', 'url']);

export function queueInitialEdgeDetection(store, target, now = target.created_at ?? new Date().toISOString()) {
  if (!INITIAL_EDGE_KINDS.includes(target.kind)) return null;
  store.initialEdgeDetections ??= [];
  const existing = store.initialEdgeDetections.find((row) => row.tenant_id === target.tenant_id && row.target_id === target.id);
  if (existing) return existing;
  const request = { tenant_id: target.tenant_id, target_id: target.id, status: 'queued', requested_at: now,
    next_attempt_at: now, attempts: 0, blocked_reason: null, test_run_id: null, lease_token: null, lease_expires_at: null };
  store.initialEdgeDetections.push(request);
  return request;
}

export function presentInitialEdgeDetection(row) {
  if (!row) return null;
  return { target_id: row.target_id, status: row.status, check_id: INITIAL_EDGE_CHECK_ID,
    requested_at: row.requested_at, next_attempt_at: row.next_attempt_at,
    blocked_reason: row.blocked_reason ?? null, test_run_id: row.test_run_id ?? null };
}
