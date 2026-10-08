import './dev-data-dir.mjs';

import { PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

/** Baseline entity IDs for detail-route hash query params (`route-params.ts`). */
export const PORTAL_DETAIL_ENTITY_IDS = Object.freeze({
  'target-detail': PORTAL_BASELINE_IDS.targetId,
  'run-detail': 'run_checkout_1',
  'scan-detail': 'scan_checkout_1',
  'finding-detail': PORTAL_BASELINE_IDS.findingId,
  'report-detail': 'rpt_checkout_baseline',
  'tenant-detail': PORTAL_BASELINE_IDS.tenantId,
  'queue-detail': 'hsr_checkout_scheduled',
  'check-detail': 'origin.leak_scan.safe',
  'policy-detail': 'pol_checkout',
  'evidence-detail': 'art_probe_checkout_1',
});

/** Customer-visible sidebar routes from `navigation.ts` NAV_ITEMS (excludes staff). */
export const NAV_ROUTE_IDS = Object.freeze([
  'dashboard',
  'targets',
  'checks',
  'test-policies',
  'runs',
  'findings',
  'reports',
  'integrations',
  'notifications',
  'audit',
  'settings',
  'support',
  'subscription',
]);

/** Auditor-narrowed customer routes (`route-access.ts` ROUTE_CUSTOMER_ROLES). */
export const AUDITOR_NAV_ROUTE_IDS = Object.freeze([
  'release-evidence',
]);

/** Staff sidebar routes from `navigation.ts` NAV_ITEMS. */
export const STAFF_NAV_ROUTE_IDS = Object.freeze([
  'admin',
  'internal-soc',
]);

/** Deep-link detail routes from `navigation.ts` DETAIL_ROUTE_ITEMS. */
export const DETAIL_ROUTE_IDS = Object.freeze([
  'target-detail',
  'run-detail',
  'scan-detail',
  'finding-detail',
  'finding-group-detail',
  'report-detail',
  'tenant-detail',
  'queue-detail',
  'check-detail',
  'policy-detail',
  'evidence-detail',
]);

/** Public routes from docs/ux/14 §3.2. */
export const PUBLIC_ROUTE_ENTRIES = Object.freeze([
  { routeId: 'landing', pathname: '/' },
  { routeId: 'login', pathname: '/login' },
  { routeId: 'signup', pathname: '/signup' },
  { routeId: 'signup-status', pathname: '/signup-status' },
  { routeId: 'set-password', pathname: '/set-password' },
  { routeId: 'staff-login', pathname: '/internal/admin/login' },
]);

/**
 * FT-A11Y-01 route matrix: all app routes (NAV_ITEMS + DETAIL_ROUTE_ITEMS) + public routes.
 * @typedef {'public' | 'customer' | 'customer-auditor' | 'staff-admin' | 'staff-soc'} PortalRouteSurface
 * @typedef {{ routeId: string, surface: PortalRouteSurface, pathname?: string }} PortalRouteScan
 */

/** @type {readonly PortalRouteScan[]} */
export const ROUTES_TO_SCAN = Object.freeze([
  ...PUBLIC_ROUTE_ENTRIES.map((entry) => ({
    routeId: entry.routeId,
    surface: 'public',
    pathname: entry.pathname,
  })),
  ...NAV_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: 'customer',
  })),
  ...AUDITOR_NAV_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: 'customer-auditor',
  })),
  ...STAFF_NAV_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: routeId === 'internal-soc' ? 'staff-soc' : 'staff-admin',
  })),
  ...DETAIL_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: routeId === 'tenant-detail'
      ? 'staff-admin'
      : routeId === 'queue-detail'
        ? 'staff-soc'
        : 'customer',
  })),
]);