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

/** Pure lifecycle plan. Closure sets closed_at; reopen clears it. */
export function planFindingPatch(body = {}) {
  if (body.status == null || body.status === '') return { patch: {} };
  if (!LIFECYCLE.has(body.status)) return { error: 'invalid_lifecycle', status: 400 };
  const patch = { status: body.status };
  if (CLOSURE_STATUSES.has(body.status)) patch.closed_at = new Date().toISOString();
  else if (body.status === 'open' || body.status === 'in_progress') patch.closed_at = null;
  return { patch };
}

/** finding:write, checked before requirePermission so an allowed role does not record a false denial. */
export function authorizeFindingWrite(ctx) {
  const roleOk = roleHasPermission(ctx?.role, 'finding:write');
  const scopes = ctx?.scopes;
  const scopeOk = !Array.isArray(scopes) || scopes.includes('*') || scopes.includes('finding:write');
  if (roleOk && scopeOk) return { ok: true };
  return requirePermission(ctx, 'finding:write', { resource_type: 'finding' });
}
