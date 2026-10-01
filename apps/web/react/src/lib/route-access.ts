import type { RouteId } from './types';
import { staffSessionHasPermission } from './dataset-access.mjs';

/** Align with `isStaffSocRole` in api.ts — operational SOC staff only. */
const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

/**
 * Permission keys used by route gates — keep aligned with `src/contracts/roles.mjs` PERMISSIONS.
 * Node tests import `route-access.mjs`, which delegates to `roleHasPermission` from roles.mjs.
 */
const ROUTE_BACKEND_PERMISSIONS: Record<string, readonly string[]> = {
  'notification:read': ['owner', 'admin', 'engineer', 'soc', 'auditor'],
  'audit:read': ['owner', 'admin', 'soc', 'auditor'],
  'report:read': ['owner', 'admin', 'engineer', 'soc', 'auditor', 'viewer'],
  'release_evidence:read': ['owner', 'admin', 'soc', 'auditor'],
  'soc:high_scale': ['soc'],
};

/** Customer portal routes gated by backend RBAC keys in `src/contracts/roles.mjs`. */
const ROUTE_PERMISSION: Partial<Record<RouteId, string>> = {
  notifications: 'notification:read',
  audit: 'audit:read',
  reports: 'report:read',
  'release-evidence': 'release_evidence:read',
};

/**
 * Routes narrowed below their backend permission (docs/ux/14 §3.1 deleted the
 * customer-facing release-evidence surface; auditor keeps the landing page).
 */
const ROUTE_CUSTOMER_ROLES: Partial<Record<RouteId, readonly string[]>> = {
  'release-evidence': ['auditor'],
};

const STAFF_ONLY_ROUTES = new Set<RouteId>(['admin', 'tenant-detail']);
/**
 * SOC execution console. Two distinct planes share this route id:
 *   - customer `soc` role → tenant-scoped console (SocConsolePage staffSocSurface=false),
 *     gated on the `soc:high_scale` backend permission (engineers/viewers lack it);
 *   - staff `soc_analyst`/`soc_lead` → cross-tenant staff console (staffSocSurface=true).
 * queue-detail is shared: customers complete packs; staff run lifecycle.
 */
const SOC_CONSOLE_ROUTES = new Set<RouteId>(['internal-soc']);

export type RouteAccessContext = {
  principal?: string;
  staffRole?: string;
};

function roleHasPermission(role: string, permission: string): boolean {
  const allowed = ROUTE_BACKEND_PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(role);
}

export function canAccessRoute(
  role: string | undefined,
  routeId: RouteId,
  context: RouteAccessContext = {}
): boolean {
  const normalizedRole = String(role ?? '').trim().toLowerCase();
  const principal = String(context.principal ?? 'customer').trim().toLowerCase();
  const staffRole = String(context.staffRole ?? '').trim().toLowerCase();

  if (STAFF_ONLY_ROUTES.has(routeId)) {
    if (principal !== 'staff') return false;
    // The tenant record API requires staff:tenant:read (SOC roles lack it). Without this gate a
    // SOC analyst lands on a page of fallback values presented as the tenant's real state.
    return routeId !== 'tenant-detail'
      || staffSessionHasPermission({ principal, staff_role: staffRole }, 'staff:tenant:read');
  }

  if (SOC_CONSOLE_ROUTES.has(routeId)) {
    // Staff SOC roles reach the cross-tenant staff console.
    if (principal === 'staff') return STAFF_SOC_ROLES.has(staffRole);
    // Customer `soc` reaches the tenant-scoped console iff it holds the SOC
    // high-scale permission. Engineers/viewers lack `soc:high_scale` and stay
    // denied. This does not weaken server RBAC or expose cross-tenant reads —
    // the tenant console uses tenant-scoped /internal/soc/* APIs only.
    return roleHasPermission(normalizedRole, 'soc:high_scale');
  }

  // Customer datasets intentionally do not hydrate for a non-impersonating staff
  // session. Keep those routes out of the staff surface rather than rendering
  // their fallbacks as authoritative empty tenant state. Queue detail remains
  // shared, but staff access requires an operational SOC role.
  if (principal === 'staff') {
    return routeId === 'queue-detail' && STAFF_SOC_ROLES.has(staffRole);
  }

  const narrowedRoles = ROUTE_CUSTOMER_ROLES[routeId];
  if (narrowedRoles && !narrowedRoles.includes(normalizedRole)) {
    return false;
  }

  const permission = ROUTE_PERMISSION[routeId];
  if (!permission) {
    return true;
  }

  return roleHasPermission(normalizedRole, permission);
}