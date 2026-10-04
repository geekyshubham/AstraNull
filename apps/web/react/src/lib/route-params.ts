function routeQueryParams() {
  const hash = window.location.hash.replace(/^#/, '');
  const queryInHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  return new URLSearchParams(queryInHash || window.location.search);
}

export function getRouteEntityId(fallback = '') {
  const params = routeQueryParams();
  return params.get('id') ?? params.get('entity_id') ?? fallback;
}

/** Optional tenant scope for staff SOC cross-tenant detail links. */
export function getRouteTenantId(fallback = '') {
  const params = routeQueryParams();
  return params.get('tenant') ?? params.get('tenant_id') ?? fallback;
}

export function buildDetailHref(route: string, id: string, extras: { tenantId?: string } = {}) {
  const encoded = encodeURIComponent(id);
  const tenant = String(extras.tenantId ?? '').trim();
  const tenantQs = tenant ? `&tenant=${encodeURIComponent(tenant)}` : '';
  return `${window.location.pathname}${window.location.search}#${route}?id=${encoded}${tenantQs}`;
}
export {
  buildEvidenceInspectorHref,
  closeEvidenceInspector,
  openEvidenceInspector,
  parseInspectorRef,
  replaceEvidenceInspector,
  sanitizeRouteParams,
  stripInspectorParams,
} from './evidence-inspector.mjs';
import { sanitizeRouteParams } from './evidence-inspector.mjs';
export type { EvidenceInspectorRef } from './evidence-inspector.mjs';

/** Read one allowlisted hash query parameter for the current route. */
export function getRouteParam(name: string, fallback = '') {
  return routeQueryParams().get(name) ?? fallback;
}

/**
 * Update hash query parameters on the current route without a history entry. Only the defined
 * route/filter/inspector parameters survive (see `sanitizeRouteParams`); unknown keys and
 * credential-like values already in the address are dropped rather than copied forward.
 */
export function replaceRouteParams(updates: Record<string, string | null | undefined>) {
  const hash = window.location.hash.replace(/^#/, '');
  const index = hash.indexOf('?');
  const route = index >= 0 ? hash.slice(0, index) : hash;
  const merged = new URLSearchParams(index >= 0 ? hash.slice(index + 1) : '');
  for (const [key, value] of Object.entries(updates)) {
    if (value === null || value === undefined || value === '') merged.delete(key);
    else merged.set(key, value);
  }
  const params = sanitizeRouteParams(merged);
  const query = params.toString();
  const next = `${window.location.pathname}${window.location.search}#${route}${query ? `?${query}` : ''}`;
  if (next !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
    window.history.replaceState(window.history.state, '', next);
  }
}
