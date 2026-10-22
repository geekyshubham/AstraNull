import { CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES, ACTION_STATES } from '../fixtures/portal-action-coverage.mjs';
import { buildPortalActionCoverage, assertPortalActionCell, findPortalSourceAction } from './portal-action-coverage.mjs';
import { buildPortalActionInventory, inventorySourceDigest } from './portal-action-inventory.mjs';
import { collectPortalBrowserFailures } from './portal-browser-failures.mjs';
import { installPortalBrowserResources } from './portal-browser-resources.mjs';
import { getPortalPlaywrightBaseUrl } from './portal-playwright-server.mjs';
import { gotoPortalRoute, PORTAL_SESSION } from './portal-playwright-session.mjs';

export const PORTAL_SESSION_KEY = 'astranull.portal.session.v1';
const MUTATING = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

export function matrixIdentities() {
  return [
    ...CUSTOMER_ACTION_ROLES.map((role) => ({ principal: 'customer', role, label: `customer ${role}`, session: { ...PORTAL_SESSION, role, user_id: `usr_${role}` } })),
    ...STAFF_ACTION_ROLES.map((role) => ({ principal: 'staff', role, label: `staff ${role}`, session: { mode: 'dev-headers', principal: 'staff', staff_role: role, role, staff_id: `staff_${role}` } })),
  ];
}

/** Seeds the identity once per tab so a sign-out stays signed out across the following navigation. */
export async function openMatrixSession(page, identity) {
  await installPortalBrowserResources(page);
  await page.addInitScript(({ key, session }) => {
    if (sessionStorage.getItem('__matrixSeeded')) return;
    sessionStorage.setItem('__matrixSeeded', '1');
    sessionStorage.setItem(key, JSON.stringify(session));
  }, { key: PORTAL_SESSION_KEY, session: identity.session });
}

export async function restoreMatrixSession(page, identity) {
  await page.evaluate(({ key, session }) => sessionStorage.setItem(key, JSON.stringify(session)), { key: PORTAL_SESSION_KEY, session: identity.session });
}

export function recordRequests(page) {
  const entries = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (/^\/(?:v1|internal)\//.test(url.pathname)) entries.push({ method: request.method(), path: url.pathname, search: url.search });
  });
  return {
    mark: () => entries.length,
    since: (mark = 0) => entries.slice(mark),
    writesSince: (mark = 0) => entries.slice(mark).filter((entry) => MUTATING.has(entry.method)),
  };
}

export function createActionMatrix({ files, inventory = buildPortalActionInventory(), coverage = buildPortalActionCoverage({ inventory }) } = {}) {
  const wanted = new Set(inventory.actions.filter((action) => files.some((file) => action.file.endsWith(file))).map((action) => action.id));
  const byIdentity = new Map();
  for (const cell of coverage.cells) {
    if (cell.applicable !== true || !wanted.has(cell.action)) continue;
    const identity = `${cell.principal}|${cell.role}`;
    if (!byIdentity.has(identity)) byIdentity.set(identity, new Map());
    const routes = byIdentity.get(identity);
    if (!routes.has(cell.route)) routes.set(cell.route, new Map());
    const actions = routes.get(cell.route);
    if (!actions.has(cell.action)) actions.set(cell.action, new Map());
    actions.get(cell.action).set(cell.state, cell);
  }
  return {
    inventory,
    coverage,
    sourceDigest: inventorySourceDigest(inventory),
    cellsFor: (identity) => byIdentity.get(`${identity.principal}|${identity.role}`) ?? new Map(),
    cellCount: (identity) => [...(byIdentity.get(`${identity.principal}|${identity.role}`)?.values() ?? [])].reduce((total, actions) => total + [...actions.values()].reduce((sum, states) => sum + states.size, 0), 0),
  };
}

/**
 * Drives every applicable cell of one identity. A driver names one shipped source action and one
 * behavior function per state; the runner derives route/role/state applicability from source and
 * fails when an applicable cell has no behavior function, so a new UI action cannot go unnoticed.
 */
export async function runIdentityMatrix(matrix, { page, testInfo, identity, drivers, arrive, failures, requests, context = {} }) {
  const baseUrl = getPortalPlaywrightBaseUrl();
  const bound = drivers.map((driver) => ({ ...driver, action: findPortalSourceAction(matrix.inventory, driver.query) }));
  const driven = new Set(bound.map((driver) => driver.action.id));
  const cells = matrix.cellsFor(identity);
  const missing = [];
  const executed = [];
  for (const [route, actions] of cells) {
    for (const actionId of actions.keys()) if (!driven.has(actionId)) missing.push(`${route}|${actionId}|*`);
  }
  const defaultArrive = (route) => gotoPortalRoute(page, route, baseUrl);
  const arriveAt = arrive ?? defaultArrive;
  const only = process.env.PORTAL_MATRIX_ROUTES ? new Set(process.env.PORTAL_MATRIX_ROUTES.split(',')) : null;
  for (const [route, actions] of cells) {
    if (only && !only.has(route)) continue;
    await arriveAt(route);
    failures?.assertClean();
    const ctx = { page, testInfo, identity, route, baseUrl, failures, requests, matrix, arrive: arriveAt, ...context };
    for (const driver of bound) {
      const states = actions.get(driver.action.id);
      if (!states) continue;
      const order = driver.order ?? ACTION_STATES;
      for (const state of order.filter((candidate) => states.has(candidate))) {
        const behavior = driver.states[state];
        if (!behavior) { missing.push(`${route}|${driver.action.id}|${state}`); continue; }
        const cell = states.get(state);
        if (process.env.PORTAL_MATRIX_TRACE) process.stdout.write(`${identity.label} ${route} ${state} ${driver.action.id.split('#')[1]}\n`);
        await assertPortalActionCell(testInfo, { action: driver.action.id, route, principal: identity.principal, role: identity.role, dataset: cell.dataset, state, channel: 'ui', sourceDigest: matrix.sourceDigest }, () => behavior({ ...ctx, cell }));
        executed.push(cell.id);
      }
      for (const state of states.keys()) if (!order.includes(state)) missing.push(`${route}|${driver.action.id}|${state}`);
      if (driver.settle) await driver.settle(ctx);
    }
    failures?.assertClean();
  }
  if (missing.length) throw new Error(`${missing.length} applicable ${identity.label} cells have no behavior driver:\n${missing.slice(0, 20).join('\n')}`);
  return executed;
}

export async function startMatrixPage(page, identity, { allowResponse } = {}) {
  const failures = await collectPortalBrowserFailures(page, getPortalPlaywrightBaseUrl(), allowResponse ? { allowResponse } : undefined);
  const requests = recordRequests(page);
  await openMatrixSession(page, identity);
  return { failures, requests };
}
