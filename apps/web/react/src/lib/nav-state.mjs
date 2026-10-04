/**
 * Allowlisted list return state (filters, sort, page, selection, scroll, focus) scoped to one
 * tenant, user and role. Stored in sessionStorage with a TTL; never holds tokens or drafts.
 */

import { looksLikeCredential } from './evidence-inspector.mjs';

export const NAV_STATE_PREFIX = 'astranull.nav.v1:';

/**
 * Filter keys list pages actually support. Values are short enumerations or labels; `q` is
 * bounded free text. Unknown keys (arbitrary metadata, payload fields) are never persisted.
 */
export const NAV_FILTER_KEYS = Object.freeze({
  q: 'search',
  search: 'search',
  status: 'slug',
  severity: 'slug',
  owner: 'label',
  group: 'token',
  kind: 'slug',
  tag: 'label',
  verification: 'slug',
  family: 'slug',
  family_status: 'slug',
  service_role: 'slug',
  criticality: 'slug',
  owner_status: 'slug',
  freshness: 'slug',
  unit: 'slug',
  has_open_finding: 'slug',
  target_group_id: 'token',
  verification_state: 'slug',
});
export const NAV_STATE_TTL_MS = 30 * 60 * 1000;

const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:@ /-]{0,119}$/;
const SAFE_SLUG = /^[a-z0-9][a-z0-9_.-]{0,63}$/i;
const MAX_EXPANDED = 50;

function text(value) {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function safeToken(value) {
  const candidate = text(value);
  return SAFE_TOKEN.test(candidate) && !looksLikeCredential(candidate) ? candidate : '';
}

function safeFilterValue(rule, value) {
  const candidate = text(value);
  if (!candidate || looksLikeCredential(candidate) || /[\u0000-\u001f\u007f]/.test(candidate)) return '';
  if (rule === 'search') return candidate.slice(0, 120) === candidate ? candidate : '';
  if (rule === 'slug') return SAFE_SLUG.test(candidate) ? candidate : '';
  if (rule === 'label') return candidate.length <= 80 && /^[\w .:@/+-]+$/.test(candidate) ? candidate : '';
  return safeToken(candidate);
}

function safeInt(value, max = 1_000_000) {
  const number = Math.trunc(Number(value));
  return Number.isFinite(number) && number >= 0 && number <= max ? number : null;
}

/** tenant|user|role scope; '' when the session lacks a tenant (no persistence then). */
export function navScopeKey(session) {
  const source = record(session) ?? {};
  const tenant = safeToken(source.tenant_id);
  if (!tenant) return '';
  const user = safeToken(source.user_id) || safeToken(source.staff_id) || 'anon';
  const role = safeToken(source.role) || safeToken(source.staff_role) || 'none';
  return `${tenant}|${user}|${role}`;
}

/** Keep only allowlisted, non-sensitive fields with bounded sizes. */
export function sanitizeNavState(input) {
  const state = record(input) ?? {};
  const out = {};
  const filters = record(state.filters);
  if (filters) {
    const safe = {};
    for (const [key, rule] of Object.entries(NAV_FILTER_KEYS)) {
      if (!Object.hasOwn(filters, key)) continue;
      const cleaned = safeFilterValue(rule, filters[key]);
      if (cleaned) safe[key] = cleaned;
    }
    if (Object.keys(safe).length) out.filters = safe;
  }
  for (const field of ['sort', 'view', 'tab', 'check', 'selectedRowId', 'focusKey']) {
    const value = safeToken(state[field]);
    if (value) out[field] = value;
  }
  const page = safeInt(state.page, 100_000);
  if (page !== null) out.page = page;
  const pageSize = safeInt(state.pageSize, 1000);
  if (pageSize) out.pageSize = pageSize;
  const scrollTop = safeInt(state.scrollTop, 10_000_000);
  if (scrollTop !== null) out.scrollTop = scrollTop;
  if (Array.isArray(state.expanded)) {
    const expanded = state.expanded.map(safeToken).filter(Boolean).slice(0, MAX_EXPANDED);
    if (expanded.length) out.expanded = [...new Set(expanded)];
  }
  return out;
}

function storage() {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

export function navStateStorageKey(scope, route) {
  const routeKey = safeToken(route);
  if (!scope || !routeKey) return '';
  return `${NAV_STATE_PREFIX}${scope}:${routeKey}`;
}

export function saveNavState(scope, route, state, now = Date.now()) {
  const key = navStateStorageKey(scope, route);
  const store = storage();
  if (!key || !store) return false;
  try {
    store.setItem(key, JSON.stringify({ savedAt: now, state: sanitizeNavState(state) }));
    return true;
  } catch {
    return false;
  }
}

export function loadNavState(scope, route, now = Date.now()) {
  const key = navStateStorageKey(scope, route);
  const store = storage();
  if (!key || !store) return null;
  try {
    const parsed = record(JSON.parse(store.getItem(key) ?? 'null'));
    if (!parsed) return null;
    const savedAt = Number(parsed.savedAt);
    if (!Number.isFinite(savedAt) || now - savedAt > NAV_STATE_TTL_MS || savedAt > now + 60_000) {
      store.removeItem(key);
      return null;
    }
    return sanitizeNavState(parsed.state);
  } catch {
    return null;
  }
}

/** Remove every stored list state, or only those outside `keepScope` (tenant/role change). */
export function clearNavState(keepScope = '') {
  const store = storage();
  if (!store) return;
  try {
    const doomed = [];
    for (let index = 0; index < store.length; index += 1) {
      const key = store.key(index);
      if (!key || !key.startsWith(NAV_STATE_PREFIX)) continue;
      if (keepScope && key.startsWith(`${NAV_STATE_PREFIX}${keepScope}:`)) continue;
      doomed.push(key);
    }
    doomed.forEach((key) => store.removeItem(key));
  } catch {
    // Storage blocked: nothing persisted, nothing to clear.
  }
}
