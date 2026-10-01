import { roleHasPermission } from '../../../../../src/contracts/roles.mjs';
import { staffRoleHasPermission } from '../../../../../src/contracts/staffRoles.mjs';

/** Align with isStaffSocRole in api.ts — operational SOC staff only. */
const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

/** Customer portal routes gated by backend RBAC keys in `src/contracts/roles.mjs`. */
const ROUTE_PERMISSION = Object.freeze({
  notifications: 'notification:read',
  audit: 'audit:read',
  reports: 'report:read',
  'release-evidence': 'release_evidence:read',
});

/** Routes narrowed below their backend permission (docs/ux/14 §3.1). Keep in sync with route-access.ts. */
const ROUTE_CUSTOMER_ROLES = Object.freeze({
  'release-evidence': Object.freeze(['auditor']),
});

const STAFF_ONLY_ROUTES = new Set(['admin', 'tenant-detail']);
/**
 * SOC execution console. Customer `soc` → tenant-scoped console (gated on the
 * `soc:high_scale` backend permission); staff `soc_analyst`/`soc_lead` →
 * cross-tenant staff console. queue-detail is shared for customer pack completion.
 */
const SOC_CONSOLE_ROUTES = new Set(['internal-soc']);

/**
 * @param {string | undefined} role
 * @param {string} routeId
 * @param {{ principal?: string; staffRole?: string }} [context]
 */
export function canAccessRoute(role, routeId, context = {}) {
  const normalizedRole = String(role ?? '').trim().toLowerCase();
  const principal = String(context.principal ?? 'customer').trim().toLowerCase();
  const staffRole = String(context.staffRole ?? '').trim().toLowerCase();

  if (STAFF_ONLY_ROUTES.has(routeId)) {
    if (principal !== 'staff') return false;
    // The tenant record API requires staff:tenant:read (SOC roles lack it). Without this gate a
    // SOC analyst lands on a page of fallback values presented as the tenant's real state.
    return routeId !== 'tenant-detail' || staffRoleHasPermission(staffRole, 'staff:tenant:read');
  }

  if (SOC_CONSOLE_ROUTES.has(routeId)) {
    // Staff SOC roles reach the cross-tenant staff console.
    if (principal === 'staff') return STAFF_SOC_ROLES.has(staffRole);
    // Customer `soc` reaches the tenant-scoped console iff it holds the SOC
    // high-scale permission. Engineers/viewers lack `soc:high_scale` and stay
    // denied. Server RBAC is unchanged; the tenant console uses tenant-scoped
    // /internal/soc/* APIs only (no cross-tenant reads).
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