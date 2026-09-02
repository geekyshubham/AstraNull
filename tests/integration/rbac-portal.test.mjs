/**
 * Portal revamp RBAC integration tests (docs/ux/17 §7).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { roleHasPermission } from '../../src/contracts/roles.mjs';
import { STAFF_ROLES } from '../../src/contracts/staffRoles.mjs';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';
import { DETAIL_ROUTE_ITEMS, NAV_ITEMS } from '../../apps/web/react/src/lib/navigation.ts';

/** Every shipped authenticated route, derived from the same source as the router and shell. */
const PORTAL_ROUTES = Object.freeze(
  [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => item.id),
);

/** Every shipped sidebar entry, including customer and staff surfaces. */
const SIDEBAR_ROUTE_IDS = Object.freeze(NAV_ITEMS.map((item) => item.id));

const STAFF_ONLY_ROUTES = new Set(['admin', 'tenant-detail']);
/** Staff-only SOC execution console. queue-detail is shared for customer pack completion. */
const STAFF_SOC_ROUTES = new Set(['internal-soc']);
const PERMISSION_GATED_ROUTES = Object.freeze({
  notifications: 'notification:read',
  audit: 'audit:read',
  reports: 'report:read',
  'release-evidence': 'release_evidence:read',
});

/**
 * Routes narrowed below their backend permission. docs/ux/14 §3.1 deleted the customer-facing
 * release-evidence surface; the auditor role keeps `release_evidence:read` and the landing page.
 */
const CUSTOMER_ROLE_NARROWED_ROUTES = Object.freeze({
  'release-evidence': Object.freeze(['auditor']),
});

const CUSTOMER_ROLES = ['owner', 'engineer', 'viewer', 'auditor', 'admin', 'soc'];
/** Operational SOC staff roles only (matches isStaffSocRole / route-access). */
const STAFF_SOC_ROLES = ['soc_analyst', 'soc_lead'];

function expectedCustomerAccess(role, routeId) {
  if (STAFF_ONLY_ROUTES.has(routeId) || STAFF_SOC_ROUTES.has(routeId)) {
    return false;
  }
  const narrowedRoles = CUSTOMER_ROLE_NARROWED_ROUTES[routeId];
  if (narrowedRoles && !narrowedRoles.includes(role)) {
    return false;
  }
  const permission = PERMISSION_GATED_ROUTES[routeId];
  if (permission) {
    return roleHasPermission(role, permission);
  }
  return true;
}

function filterSidebar(role, principal, staffRole) {
  return SIDEBAR_ROUTE_IDS.filter((routeId) =>
    canAccessRoute(role, routeId, { principal, staffRole }),
  );
}

describe('portal RBAC matrix (FT-RBAC-01..03)', () => {
  it('FT-RBAC-01 customer route-access matches roles.mjs permission gates', () => {
    for (const role of CUSTOMER_ROLES) {
      for (const routeId of PORTAL_ROUTES) {
        const allowed = canAccessRoute(role, routeId, { principal: 'customer' });
        const expected = expectedCustomerAccess(role, routeId);
        assert.equal(
          allowed,
          expected,
          `role=${role} route=${routeId} expected=${expected} got=${allowed}`,
        );
      }
    }
  });

  it('FT-RBAC-02 staff-only surfaces are absent from every non-staff sidebar', () => {
    for (const role of CUSTOMER_ROLES) {
      const visible = filterSidebar(role, 'customer');
      for (const routeId of STAFF_ONLY_ROUTES) {
        assert.equal(
          visible.includes(routeId),
          false,
          `customer role=${role} must not see staff route ${routeId}`,
        );
      }
      assert.equal(visible.includes('internal-soc'), false);
    }
  });

  it('FT-RBAC-03 SOC console requires staff principal with SOC staff role', () => {
    for (const role of CUSTOMER_ROLES) {
      assert.equal(
        canAccessRoute(role, 'internal-soc', { principal: 'customer' }),
        false,
        `customer principal must not access internal-soc (role=${role})`,
      );
    }

    assert.equal(
      canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }),
      false,
    );

    for (const staffRole of STAFF_SOC_ROLES) {
      assert.equal(
        canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole }),
        true,
        `staff SOC role ${staffRole} must access internal-soc`,
      );
      assert.equal(
        canAccessRoute('admin', 'queue-detail', { principal: 'staff', staffRole }),
        true,
        `staff SOC role ${staffRole} must access queue-detail`,
      );
    }
  });
});

describe('portal staff/customer surface separation (FT-RBAC-04)', () => {
  it('FT-RBAC-04 staff principals can reach only staff routes authorized for their staff role', () => {
    for (const staffRole of STAFF_ROLES) {
      const expectedRoutes = new Set(['admin', 'tenant-detail']);
      if (STAFF_SOC_ROLES.includes(staffRole)) {
        expectedRoutes.add('internal-soc');
        expectedRoutes.add('queue-detail');
      }

      for (const routeId of PORTAL_ROUTES) {
        assert.equal(
          canAccessRoute('admin', routeId, { principal: 'staff', staffRole }),
          expectedRoutes.has(routeId),
          `staff_role=${staffRole} route=${routeId}`,
        );
      }

      assert.deepEqual(
        filterSidebar('admin', 'staff', staffRole),
        STAFF_SOC_ROLES.includes(staffRole) ? ['admin', 'internal-soc'] : ['admin'],
        `staff_role=${staffRole} sidebar`,
      );
    }
  });
});
