import { expect, test } from '@playwright/test';
import { roleHasPermission } from '../../../src/contracts/roles.mjs';
import { staffRoleHasPermission } from '../../../src/contracts/staffRoles.mjs';
import { collectPortalBrowserFailures } from '../../helpers/portal-browser-failures.mjs';
import { inventorySourceDigest } from '../../helpers/portal-action-inventory.mjs';
import { canReadDataset, CUSTOMER_DATASET_PERMISSIONS } from '../../../apps/web/react/src/lib/dataset-access.mjs';
import { canAccessRoute } from '../../../apps/web/react/src/lib/route-access.mjs';
import { CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES } from '../../fixtures/portal-action-coverage.mjs';
import { buildPortalActionInventory, enumeratePortalRuntimeActions, assertSourcePortalAction, assertPortalActionCell, portalDatasetReadDimensions } from '../../helpers/portal-action-coverage.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, resolvePortalRouteUrl, injectPortalDevHeadersSession, PORTAL_SESSION } from '../../helpers/portal-playwright-session.mjs';

const inventory = buildPortalActionInventory();
const sourceDigest = inventorySourceDigest(inventory);
const browserDiagnostics = new WeakMap();
const restrictedDatasetPaths = { internalOverview: '/internal/admin/overview', internalSignupRequests: '/internal/admin/signup-requests', internalTenants: '/internal/admin/tenants', internalApprovalRequests: '/internal/admin/approval-requests', internalAudit: '/internal/admin/audit-log', audit: '/v1/audit-log', releaseEvidence: '/v1/production-release-evidence', releaseAttestation: '/v1/production-release-evidence/attestation', notifications: '/v1/notifications', connectors: '/v1/connectors', secrets: '/v1/secrets', serviceAccounts: '/v1/service-accounts' };
async function assertDatasetOutcomes(testInfo, responses, identity) {
  for (const dimension of portalDatasetReadDimensions().filter((item) => item.principal === identity.principal && item.role === identity.role)) await assertPortalActionCell(testInfo, { action: `dataset:${dimension.datasetId}`, route: dimension.route, principal: identity.principal, role: identity.role, dataset: 'baseline', state: dimension.hydrationAllowed ? 'success' : 'denial', channel: 'ui', sourceDigest }, async () => {
    const path = restrictedDatasetPaths[dimension.datasetId];
    const matching = responses.filter((response) => response.path === path || response.path.startsWith(`${path}/`));
    if (dimension.hydrationAllowed) { expect(matching.length, `Permitted ${dimension.datasetId} dataset hydrated for ${identity.role}`).toBeGreaterThan(0); expect(matching.every((response) => response.status === 200)).toBe(true); }
    else expect(matching, `Suppressed ${dimension.datasetId} dataset HTTP reads for ${identity.role}`).toEqual([]);
    return [`Actual ${identity.principal}/${identity.role} ${dimension.datasetId}: permissionReadable=${dimension.readable}; callerRouteAllowed=${dimension.routeAllowed}; ${dimension.hydrationAllowed ? 'permitted GET completed HTTP200' : dimension.readable ? 'narrower UI route suppressed hydration, not a backend dataset denial' : 'dataset permission prohibited hydration and no request was issued'}`];
  });
}
async function assertRouteOutcome(testInfo, page, identity, route, allowed) {
  await assertPortalActionCell(testInfo, { action: `route:${route}`, route, principal: identity.principal, role: identity.role, dataset: 'baseline', state: allowed ? 'success' : 'denial', channel: 'ui', sourceDigest }, async () => {
    await expect(page).toHaveURL(resolvePortalRouteUrl(route, getPortalPlaywrightBaseUrl()));
    if (allowed) { await expect(page.locator('.route-transition')).toBeVisible(); await expect(page.getByRole('heading', { name: 'You do not have access to this page.', exact: true })).toHaveCount(0); }
    else await expect(page.getByRole('heading', { name: 'You do not have access to this page.', exact: true })).toBeVisible();
    return [`Actual ${identity.principal}/${identity.role} direct-load ${route}: exact URL preserved and ${allowed ? 'routed surface rendered without access-denied heading' : 'explicit route denial rendered'}`];
  });
}
const affordances = [
  { route: 'targets', name: 'Add target', permission: 'target_group:write' },
  { route: 'runs', name: 'Start validation scan', permission: 'test_run:start' },
  { route: 'reports', name: 'Review report', permission: 'report:create' },
  { route: 'settings', name: 'Save organization', permission: 'tenant:write' },
  { route: 'integrations', name: 'Add provider', permission: 'target_group:write' },
];

async function attachEnumeration(testInfo, page, identity, route, dataset = 'baseline') {
  const runtime = await enumeratePortalRuntimeActions(page, { route, role: identity.role, principal: identity.principal, dataset });
  await testInfo.attach(`portal-runtime-actions-${identity.principal}-${identity.role}-${route}-${dataset}`, { body: JSON.stringify(runtime), contentType: 'application/json' });
  // The attachment is discoverability only. It is deliberately not an executed action-state receipt.
  expect(runtime.controls.every((control) => typeof control.name === 'string' && typeof control.keyboard === 'string')).toBe(true);
}

test.describe('all six actual customer and six separate staff roles: routed runtime action enumeration', () => {
  test.beforeAll(async () => { await startPortalPlaywrightServer({ liveSource: true }); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });
  test.afterEach(async ({ page }) => { browserDiagnostics.get(page)?.assertClean(); });

  for (const role of CUSTOMER_ACTION_ROLES) test(`customer ${role}: shipped routes, separate permitted affordances and explicit action denial`, async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    const failures = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl());
    browserDiagnostics.set(page, failures);
    const responses = [];
    page.on('response', (response) => { if (response.request().method() === 'GET') responses.push({ path: new URL(response.url()).pathname, status: response.status() }); });
    await injectPortalDevHeadersSession(page, { ...PORTAL_SESSION, role, user_id: `usr_${role}` });
    const writes = [];
    const reads = [];
    page.on('request', (request) => { if (/\/(?:v1|internal)\//.test(request.url())) { if (request.method() === 'GET') reads.push(new URL(request.url()).pathname); if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method())) writes.push(request.url()); } });
    for (const route of inventory.routes) {
      await gotoPortalRoute(page, route, getPortalPlaywrightBaseUrl());
      const allowed = canAccessRoute(role, route, { principal: 'customer' });
      failures.assertClean();
      await assertRouteOutcome(testInfo, page, { principal: 'customer', role }, route, allowed);
      await attachEnumeration(testInfo, page, { principal: 'customer', role }, route);
      for (const affordance of affordances.filter((item) => item.route === route)) {
        const action = page.getByRole('button', { name: affordance.name, exact: true });
        if (roleHasPermission(role, affordance.permission) || (route === 'integrations' && roleHasPermission(role, 'waf:connector_write'))) await expect(action).toBeVisible();
        else await expect(action).toHaveCount(0);
      }
      if (route === 'settings') {
        await page.getByRole('tab', { name: 'Access', exact: true }).click();
        const create = page.getByRole('button', { name: 'Create service account', exact: true });
        if (roleHasPermission(role, 'service_account:create')) await expect(create).toBeVisible();
        else await assertSourcePortalAction(testInfo, inventory, { owner: 'SettingsPage', handler: 'handleCreateServiceAccount', kind: 'form-keyboard' }, 'denial', async () => {
          await expect(create).toHaveCount(0);
          await expect(page.getByRole('button', { name: /^Rotate secret for/ })).toHaveCount(0);
          await expect(page.getByRole('button', { name: /^Revoke / })).toHaveCount(0);
          return ['Read-only role sees no create/rotate/revoke automation controls, without forbidden mutation requests'];
        }, { route, role });
        await page.getByRole('tab', { name: 'Security', exact: true }).click();
        const store = page.getByRole('button', { name: 'Store secret', exact: true });
        if (roleHasPermission(role, 'secret:write')) await expect(store).toBeVisible();
        else await assertSourcePortalAction(testInfo, inventory, { owner: 'SettingsPage', handler: 'handleCreateVaultSecret', kind: 'form-keyboard' }, 'denial', async () => {
          await expect(store).toHaveCount(0); await expect(page.getByRole('button', { name: 'Rotate secret', exact: true })).toHaveCount(0);
          return ['Role lacking vault mutation permission sees neither store nor rotate credential forms'];
        }, { route, role });
      }
    }
    failures.assertClean();
    await assertDatasetOutcomes(testInfo, responses, { principal: 'customer', role });
    expect(writes).toEqual([]);
    for (const dataset of Object.keys(CUSTOMER_DATASET_PERMISSIONS)) if (!canReadDataset({ role }, dataset)) expect(reads.filter((path) => path === restrictedDatasetPaths[dataset] || path.startsWith(`${restrictedDatasetPaths[dataset]}/`)), `Forbidden ${dataset} read for ${role}`).toEqual([]);
  });

  for (const role of STAFF_ACTION_ROLES) test(`staff ${role}: separate internal route/data/action permissions`, async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    const failures = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl());
    browserDiagnostics.set(page, failures);
    const responses = [];
    page.on('response', (response) => { if (response.request().method() === 'GET') responses.push({ path: new URL(response.url()).pathname, status: response.status() }); });
    await injectPortalDevHeadersSession(page, { mode: 'dev-headers', principal: 'staff', staff_role: role, role, staff_id: `staff_${role}` });
    const requests = [];
    page.on('request', (request) => { if (/\/(?:v1|internal)\//.test(request.url())) requests.push({ method: request.method(), path: new URL(request.url()).pathname }); });
    for (const route of inventory.routes) {
      await gotoPortalRoute(page, route, getPortalPlaywrightBaseUrl());
      const allowed = canAccessRoute(undefined, route, { principal: 'staff', staffRole: role });
      failures.assertClean();
      await assertRouteOutcome(testInfo, page, { principal: 'staff', role }, route, allowed);
      await attachEnumeration(testInfo, page, { principal: 'staff', role }, route);
    }
    await gotoPortalRoute(page, 'admin', getPortalPlaywrightBaseUrl());
    if (staffRoleHasPermission(role, 'staff:tenant:write')) await expect(page.getByRole('tab', { name: 'Tenants', exact: true })).toBeVisible();
    if (!staffRoleHasPermission(role, 'staff:signup:decide')) {
      await expect(page.getByRole('button', { name: /^Approve sign.?up/ })).toHaveCount(0);
      await expect(page.getByRole('button', { name: /^Reject sign.?up/ })).toHaveCount(0);
    }
    failures.assertClean();
    await assertDatasetOutcomes(testInfo, responses, { principal: 'staff', role });
    expect(requests.filter((request) => ['POST', 'PATCH', 'DELETE', 'PUT'].includes(request.method))).toEqual([]);
    expect(requests.filter((request) => request.path.startsWith('/v1/secrets') || request.path.startsWith('/v1/service-accounts'))).toEqual([]);
  });
});
