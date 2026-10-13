/**
 * Finding lifecycle shared by the dev store and the Postgres adapter.
 * Closure records an audited timestamp. It does not claim a fix was proved.
 */
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';

export const FINDING_LIFECYCLE = Object.freeze([
  'open', 'in_progress', 'accepted_risk', 'resolved', 'closed', 'false_positive', 'accepted',
]);
const LIFECYCLE = new Set(FINDING_LIFECYCLE);
const CLOSURE_STATUSES = new Set(['accepted_risk', 'resolved', 'closed', 'false_positive', 'accepted']);

export const RISK_ACCEPTANCE_REASON_MIN = 20;
export const RISK_ACCEPTANCE_REASON_MAX = 2000;
export const RISK_ACCEPTANCE_MAX_REVIEW_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

function riskAcceptanceRequired(message, field) {
  return { error: 'risk_acceptance_required', status: 400, field, message };
}

/** Validate the customer's risk decision; the accepting user and time come from the server. */
export function validateRiskAcceptance(input, now = new Date()) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return riskAcceptanceRequired('Accepting risk needs a reason and a review date.', 'risk_acceptance');
  }
  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  if (reason.length < RISK_ACCEPTANCE_REASON_MIN || reason.length > RISK_ACCEPTANCE_REASON_MAX) {
    return riskAcceptanceRequired(
      `The reason must be ${RISK_ACCEPTANCE_REASON_MIN} to ${RISK_ACCEPTANCE_REASON_MAX} characters.`,
      'risk_acceptance.reason',
    );
  }
  const rawReview = typeof input.review_at === 'string' ? input.review_at.trim() : '';
  const reviewMs = ISO_TIMESTAMP.test(rawReview) ? Date.parse(rawReview) : Number.NaN;
  const nowMs = now.getTime();
  if (!Number.isFinite(reviewMs) || reviewMs <= nowMs || reviewMs > nowMs + RISK_ACCEPTANCE_MAX_REVIEW_DAYS * DAY_MS) {
    return riskAcceptanceRequired(
      `The review date must be in the future and within ${RISK_ACCEPTANCE_MAX_REVIEW_DAYS} days.`,
      'risk_acceptance.review_at',
    );
  }
  return { ok: true, reason, review_at: new Date(reviewMs).toISOString() };
}

/**
 * Pure lifecycle plan. Closure sets closed_at; reopen clears it. Accepting risk needs the
 * finding:accept_risk permission and a reasoned, dated decision; any other status clears it.
 * system_summary is server-written verdict text and is never accepted from a client.
 */
export function planFindingPatch(body = {}, ctx = null, { now = new Date(), findingId = null } = {}) {
  if (body && Object.hasOwn(body, 'system_summary')) {
    return { error: 'system_summary_immutable', status: 400, message: 'The recorded explanation cannot be edited.' };
  }
  if (body.status == null || body.status === '') return { patch: {} };
  if (!LIFECYCLE.has(body.status)) return { error: 'invalid_lifecycle', status: 400 };
  const patch = { status: body.status };
  if (body.status === 'accepted_risk') {
    const allowed = authorizeRiskAcceptance(ctx, findingId);
    if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403, permission: 'finding:accept_risk' };
    const decision = validateRiskAcceptance(body.risk_acceptance, now);
    if (decision.error) return decision;
    patch.risk_acceptance = {
      reason: decision.reason,
      review_at: decision.review_at,
      accepted_by: ctx?.userId ?? null,
      accepted_at: now.toISOString(),
    };
  } else {
    patch.risk_acceptance = null;
  }
  if (CLOSURE_STATUSES.has(body.status)) patch.closed_at = now.toISOString();
  else if (body.status === 'open' || body.status === 'in_progress') patch.closed_at = null;
  return { patch };
}

function authorizeRiskAcceptance(ctx, findingId) {
  if (!ctx) return { ok: false, status: 403 };
  const scopes = ctx.scopes;
  const scopeOk = !Array.isArray(scopes) || scopes.includes('*') || scopes.includes('finding:accept_risk');
  if (roleHasPermission(ctx.role, 'finding:accept_risk') && scopeOk) return { ok: true };
  return requirePermission(ctx, 'finding:accept_risk', { resource_type: 'finding', resource_id: findingId });
}

/** finding:write, checked before requirePermission so an allowed role does not record a false denial. */
export function authorizeFindingWrite(ctx) {
  const roleOk = roleHasPermission(ctx?.role, 'finding:write');
  const scopes = ctx?.scopes;
  const scopeOk = !Array.isArray(scopes) || scopes.includes('*') || scopes.includes('finding:write');
  if (roleOk && scopeOk) return { ok: true };
  return requirePermission(ctx, 'finding:write', { resource_type: 'finding' });
}
