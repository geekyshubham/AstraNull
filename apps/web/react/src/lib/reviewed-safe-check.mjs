export const REVIEWED_SAFE_CHECK_ID = 'waf.evasion_base64_wrap.safe';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const record = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : null;
const utc = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

/** Presentation checks only. The server must reconstruct current authority at admission. */
export function reviewedSafePlanPresentation(proposal, { target, tenantId, now = Date.now() } = {}) {
  const empty = { valid: false, reason: 'operation_plan_invalid', planDigest: '', endpoint: '', expiresAt: '',
    checkVersion: '', scenarioVersion: '', maximumProbeOperations: null };
  const value = record(proposal);
  const plan = record(value?.plan);
  if (!value || !plan || value.grants_execution !== false || value.execution_available !== false
    || typeof value.plan_digest !== 'string' || !DIGEST.test(value.plan_digest)
    || plan.version !== 'reviewed-inert-operation.v1' || plan.check_id !== REVIEWED_SAFE_CHECK_ID
    || !['target_definition_digest', 'check_definition_digest'].every((key) => typeof plan[key] === 'string' && DIGEST.test(plan[key]))
    || !['check_version', 'scenario_version'].every((key) => typeof plan[key] === 'string' && plan[key].length > 0 && plan[key].length <= 256)
    || plan.template !== 'marker-query-v1' || plan.method !== 'GET'
    || plan.request_schema !== 'fixed-asn-probe-query.v1'
    || plan.semantics !== 'inert_diagnostic' || plan.side_effects !== 'none'
    || plan.maximum_body_bytes !== 0 || plan.maximum_probe_operations !== 4
    || !utc(plan.expires_at) || !Number.isFinite(now)) return empty;
  let endpoint;
  try {
    endpoint = new URL(target?.value);
    if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password
      || endpoint.search || endpoint.hash) return empty;
  } catch { return empty; }
  if (!target || target.kind !== 'url' || target.deleted_at
    || typeof tenantId !== 'string' || !ID.test(tenantId)
    || typeof target.id !== 'string' || !ID.test(target.id)
    || plan.tenant_id !== tenantId || plan.target_id !== target.id
    || (target.tenant_id != null && target.tenant_id !== tenantId)
    || plan.endpoint !== endpoint.href) return { ...empty, reason: 'operation_scope_mismatch' };
  if (Date.parse(plan.expires_at) <= now) return { ...empty, reason: 'operation_expired' };
  return { valid: true, reason: null, planDigest: value.plan_digest, endpoint: plan.endpoint,
    expiresAt: plan.expires_at, checkVersion: plan.check_version, scenarioVersion: plan.scenario_version,
    maximumProbeOperations: plan.maximum_probe_operations };
}

export function reviewedSafeReviewPresentation(review, options = {}) {
  const plan = reviewedSafePlanPresentation(review, options);
  const empty = { ...plan, reviewId: '', current: false, available: false };
  if (!plan.valid) return empty;
  const now = options.now ?? Date.now();
  if (typeof review.id !== 'string' || !ID.test(review.id)
    || typeof review.approved_by !== 'string' || !review.approved_by
    || !['owner', 'admin'].includes(review.approved_role)
    || !utc(review.approved_at) || Date.parse(review.approved_at) > now
    || Date.parse(plan.expiresAt) <= Date.parse(review.approved_at)
    || Date.parse(plan.expiresAt) - Date.parse(review.approved_at) > 24 * 60 * 60 * 1000
    || review.target_id !== options.target?.id || review.tenant_id !== options.tenantId
    || review.revoked_at != null || review.revoked_by != null
    || review.current_review_gap !== null) return { ...empty, reason: 'operation_review_not_current' };
  const availability = record(review.reviewed_execution);
  const available = availability?.available === true && availability.check_id === REVIEWED_SAFE_CHECK_ID
    && availability.reason === null;
  return { ...plan, reviewId: review.id, current: true, available,
    reason: available ? null : 'reviewed_operation_execution_unavailable' };
}

/** Never create an ordinary-run fallback for a missing, mismatched or unavailable review. */
export function reviewedSafeStartBody(review, options = {}) {
  const state = reviewedSafeReviewPresentation(review, options);
  if (!state.available || typeof options.target?.target_group_id !== 'string'
    || !ID.test(options.target.target_group_id)) return null;
  return { target_group_id: options.target.target_group_id, target_id: options.target.id,
    check_id: REVIEWED_SAFE_CHECK_ID, reviewed_operation_id: state.reviewId };
}

export function acceptedReviewedSafeExecution(response, targetId) {
  const envelope = record(response);
  const run = record(envelope?.run) ?? envelope;
  if (!run || typeof targetId !== 'string' || !ID.test(targetId)
    || typeof run.id !== 'string' || !ID.test(run.id) || run.target_id !== targetId
    || run.check_id !== REVIEWED_SAFE_CHECK_ID) return null;
  return { runId: run.id, targetId, checkId: REVIEWED_SAFE_CHECK_ID, record: run };
}
