import { createHash } from 'node:crypto';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';
import { canReadDataset, sessionHasPermission, staffSessionHasPermission, CUSTOMER_DATASET_PERMISSIONS, STAFF_DATASET_PERMISSIONS } from '../../apps/web/react/src/lib/dataset-access.mjs';
import { PORTAL_ROUTE_DATASETS } from '../../apps/web/react/src/lib/types.ts';
import { ACTION_STATES, CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES, actionStateApplicability } from '../fixtures/portal-action-coverage.mjs';
import { buildPortalActionInventory, inventorySourceDigest } from './portal-action-inventory.mjs';
import { buildPublicPortalActionInventory, buildPublicPortalActionCoverage, reconcilePublicPortalActionCoverage } from './portal-public-action-coverage.mjs';

export { buildPortalActionInventory, enumeratePortalRuntimeActions } from './portal-action-inventory.mjs';

export function findPortalSourceAction(inventory, { owner, handler, label, kind }) {
  const matches = inventory.actions.filter((action) => (!owner || action.owner === owner) && (!kind || action.kind === kind)
    && (!handler || Object.values(action.handlers).some((value) => value.includes(handler)))
    && (!label || (typeof label === 'string' ? action.label === label : label.test(action.label))));
  if (matches.length !== 1) throw new Error(`Expected one shipped semantic action, got ${matches.length}: ${JSON.stringify({ owner, handler, label: String(label ?? ''), kind })}`);
  return matches[0];
}

export async function assertSourcePortalAction(testInfo, inventory, query, state, assertBehavior, dimensions = {}) {
  const action = findPortalSourceAction(inventory, query);
  return assertPortalActionCell(testInfo, { action: action.id, route: dimensions.route ?? 'runs', principal: dimensions.principal ?? 'customer', role: dimensions.role ?? 'owner', dataset: dimensions.dataset ?? 'baseline', state, channel: 'ui', sourceDigest: inventorySourceDigest(inventory), ...dimensions }, assertBehavior);
}
export const ACTION_RECEIPT_SCHEMA = 'portal-action-execution/v1';
const STAFF_ROUTES = new Set(['admin', 'tenant-detail', 'internal-soc', 'queue-detail']);
export function portalRoleDimensions(inventory = buildPortalActionInventory()) {
  return [
    ...CUSTOMER_ACTION_ROLES.map((role) => ({ principal: 'customer', role, session: { role } })),
    ...STAFF_ACTION_ROLES.map((role) => ({ principal: 'staff', role, session: { principal: 'staff', staff_role: role } })),
  ].flatMap((identity) => inventory.routes.map((route) => ({
    ...identity, route,
    routeAllowed: canAccessRoute(identity.principal === 'customer' ? identity.role : undefined, route, { principal: identity.principal, staffRole: identity.principal === 'staff' ? identity.role : undefined }),
    datasets: (PORTAL_ROUTE_DATASETS[route] ?? []).map((dataset) => ({ dataset, readable: canReadDataset(identity.session, dataset) })),
  })));
}

export const DATASET_ACTION_ROUTES = Object.freeze({ audit: 'audit', notifications: 'notifications', connectors: 'integrations', secrets: 'settings', serviceAccounts: 'settings', internalOverview: 'admin', internalSignupRequests: 'admin', internalTenants: 'admin', internalApprovalRequests: 'admin', internalAudit: 'admin' });
// Readable over the API but with no portal caller route (docs/ux/14 §3.1); listed explicitly so new datasets cannot be skipped silently.
export const API_ONLY_DATASETS = Object.freeze(['releaseEvidence', 'releaseAttestation']);
export function unmappedPortalDatasets(permissionMaps = [CUSTOMER_DATASET_PERMISSIONS, STAFF_DATASET_PERMISSIONS]) {
  return [...new Set(permissionMaps.flatMap((permissions) => Object.keys(permissions)))]
    .filter((datasetId) => !DATASET_ACTION_ROUTES[datasetId] && !API_ONLY_DATASETS.includes(datasetId));
}
export function portalDatasetReadDimensions() {
  const unmapped = unmappedPortalDatasets();
  if (unmapped.length) throw new Error(`Dataset permissions without a DATASET_ACTION_ROUTES caller route or API_ONLY_DATASETS entry: ${unmapped.join(', ')}`);
  return [
    ...CUSTOMER_ACTION_ROLES.map((role) => ({ principal: 'customer', role, session: { role }, permissions: CUSTOMER_DATASET_PERMISSIONS })),
    ...STAFF_ACTION_ROLES.map((role) => ({ principal: 'staff', role, session: { principal: 'staff', staff_role: role }, permissions: STAFF_DATASET_PERMISSIONS }))
  ].flatMap((identity) => Object.entries(identity.permissions).filter(([datasetId]) => !API_ONLY_DATASETS.includes(datasetId)).map(([datasetId, permission]) => {
    const route = DATASET_ACTION_ROUTES[datasetId];
    const readable = canReadDataset(identity.session, datasetId);
    const routeAllowed = canAccessRoute(identity.principal === 'customer' ? identity.role : undefined, route, { principal: identity.principal, staffRole: identity.principal === 'staff' ? identity.role : undefined });
    return { ...identity, datasetId, permission, readable, routeAllowed, hydrationAllowed: readable && routeAllowed, route };
  }));
}

export function actionPermissionDecision(identity, permission) {
  return identity.principal === 'staff' ? staffSessionHasPermission(identity.session, permission) : sessionHasPermission(identity.session, permission);
}

export function actionEligibilityDecision(identity, guards = []) {
  const evaluate = (guard) => {
    if (guard.roles) { const allowed = identity.principal === guard.principal && guard.roles.includes(identity.role); return guard.invert ? !allowed : allowed; }
    if (guard.permission) {
      const allowed = identity.principal === guard.principal && actionPermissionDecision(identity, guard.permission);
      return guard.invert ? !allowed : allowed;
    }
    if (guard.operator === '&&') return evaluate(guard.left) && evaluate(guard.right);
    if (guard.operator === '||') return evaluate(guard.left) || evaluate(guard.right);
    throw new Error('Unclassified source authorization expression');
  };
  return guards.every(evaluate);
}

export function actionCellId(cell) {
  return [cell.action, cell.route, cell.principal, cell.role, cell.dataset, cell.state, cell.channel ?? 'ui'].join('|');
}

const DELEGATING_OWNERS = new Set(['Button', 'AnchorButton', 'Select', 'EmptyState', 'EmptyStateAction', 'TabButton', 'Tabs', 'ShellIconButton', 'NavLink', 'FormModal', 'ConfirmModal', 'ConfirmModalProvider', 'Toast', 'DataTableBodyRow', 'VariantSwitch']);

/** One actual action entrypoint per equivalent source callback; shared primitives delegate to semantic callsites. */
export function buildPortalActionCoverage({ inventory = buildPortalActionInventory(), publicAuth = inventory.mountSource ? buildPublicPortalActionCoverage({ inventory: buildPublicPortalActionInventory({ root: inventory.sourceRoot }) }) : null } = {}) {
  const dimensions = portalRoleDimensions(inventory);
  const routeAuthorization = dimensions.map((identity) => {
    const cell = { action: `route:${identity.route}`, route: identity.route, principal: identity.principal, role: identity.role, dataset: 'baseline', state: identity.routeAllowed ? 'success' : 'denial', channel: 'ui', applicable: true, reason: 'Exact routed access/denial is a distinct assertion from dataset reads and semantic action permissions.' };
    return { ...cell, id: actionCellId(cell) };
  });
  const datasetAuthorization = portalDatasetReadDimensions().map((identity) => {
    const cell = { action: `dataset:${identity.datasetId}`, route: identity.route, principal: identity.principal, role: identity.role, dataset: 'baseline', state: identity.hydrationAllowed ? 'success' : 'denial', channel: 'ui', applicable: true, permission: identity.permission, permissionReadable: identity.readable, routeAllowed: identity.routeAllowed, reason: identity.readable && !identity.routeAllowed ? 'Dataset permission allows this identity but its actual UI caller route is narrower; assert hydration suppression, not backend dataset denial. Backend read authorization remains a distinct boundary.' : 'Executed dataset HTTP hydration presence/success or forbidden-request absence is distinct from routed access and write affordances.' };
    return { ...cell, id: actionCellId(cell) };
  });
  const cells = [...routeAuthorization, ...datasetAuthorization];
  const semanticFamilies = [];
  const sourceAliases = [];
  for (const action of inventory.actions) {
    if (DELEGATING_OWNERS.has(action.owner)) {
      sourceAliases.push({ action: action.id, delegation: 'native/shared-control implementation', reason: 'State and permission behavior is supplied by inventoried caller props; native activation is asserted at the semantic caller, not multiplied across unrelated routes/datasets.' });
      // Keep the primitive's OWN interaction obligations. Caller business transactions
      // are separate; aliases alone are not evidence that dismiss/Escape/backdrop was tested.
    }
    const states = actionStateApplicability(action);
    const sharedShell = /components\/layout\//.test(action.file);
    const applicablePrincipals = ['customer', ...(sharedShell || action.routes.some((route) => STAFF_ROUTES.has(route)) ? ['staff'] : [])];
    const entries = [];
    for (const principal of applicablePrincipals) for (const role of principal === 'customer' ? CUSTOMER_ACTION_ROLES : STAFF_ACTION_ROLES) {
      const candidates = dimensions.filter((identity) => identity.principal === principal && identity.role === role && identity.routeAllowed && action.routes.includes(identity.route));
      // Shared mount alone proves no equivalence: App refresh/dataset/route context
      // can differ at the same source callback. Retain every actual permitted route.
      entries.push(...candidates);
    }
    semanticFamilies.push({ id: action.id, owner: action.owner, kind: action.kind, entrypoints: entries.map(({ route, principal, role, equivalentRoutes }) => ({ route, principal, role, ...(equivalentRoutes ? { equivalentRoutes, equivalence: 'Same globally mounted host and callback with no AST route branch constraint; routed outcomes have separate route authorization receipts.' } : {}) })), sourceSites: [action.id], stateApplicability: states });
    for (const identity of entries) for (const state of ACTION_STATES) {
      let applicable = states[state].applicable;
      let reason = states[state].reason;
      const guards = action.traits?.authorizationGuards ?? [];
      if (action.traits?.authorizationUnresolved && (applicable !== false || state === 'denial')) { applicable = null; reason = 'Permission references exist but their exact eligibility expression is unresolved; neither successful access nor denied access is established for this identity. This is a blocking classification gap, not N/A.'; }
      if (guards.length) {
        const eligible = actionEligibilityDecision(identity, guards);
        if (!eligible && state !== 'denial') { applicable = false; reason = 'Resolved source permission expression denies this identity; only the explicit hidden/disabled action denial is applicable, not successful transaction states.'; }
        if (state === 'denial' && (!eligible || !action.traits?.authorizationUnresolved)) { applicable = !eligible; reason = eligible ? 'This identity satisfies the resolved action guard; denial is asserted with actually denied identities instead.' : 'This identity fails the exact resolved action permission expression; assert action absence/disabled state and zero forbidden writes.'; }
      }
      const dataset = state === 'empty' ? 'empty' : 'baseline';
      const cell = { action: action.id, route: identity.route, principal: identity.principal, role: identity.role, dataset, state, channel: 'ui', applicable, reason };
      cells.push({ ...cell, id: actionCellId(cell) });
    }
  }
  return { schema: 'portal-action-coverage/v1', scope: publicAuth ? 'Authenticated customer/staff actions plus separately inventoried mounted visitor/public/auth actions; both gates must pass.' : inventory.scope, publicAuth, scopeExclusions: publicAuth ? [] : inventory.scopeExclusions, sourceDigest: inventorySourceDigest(inventory), inventory, dimensions, semanticFamilies, sourceAliases, routeAuthorization, datasetAuthorization, cells,
    unclassifiedStates: cells.filter((cell) => cell.applicable === null),
    unmappedSourceActions: inventory.actions.filter((action) => !action.routes.length).map((action) => action.id) };
}

/** Receipt creation only follows completed assertions. A reporter's PASSED test result is required before this is counted. */
export async function assertPortalActionCell(testInfo, cell, assertBehavior) {
  if (typeof assertBehavior !== 'function') throw new TypeError('Executed behavior assertions are required.');
  const observations = await assertBehavior();
  if (!Array.isArray(observations) || !observations.length || observations.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error('A receipt must name its concrete assertions, not a test filename or registry entry.');
  }
  const receipt = { schema: ACTION_RECEIPT_SCHEMA, ...cell, cellId: actionCellId(cell), observations,
    testId: testInfo.testId, titlePath: testInfo.titlePath, retry: testInfo.retry, sourceDigest: cell.sourceDigest,
    assertionCompletedAt: new Date().toISOString() };
  await testInfo.attach(`portal-action-receipt-${createHash('sha256').update(receipt.cellId).digest('hex').slice(0, 12)}`, { body: JSON.stringify(receipt), contentType: 'application/json' });
  if (process.env.EXISTING_BEHAVIOR_INVOCATION_ID) {
    const { recordExistingBehaviorReceipt } = await import('./existing-behavior-coverage.mjs');
    await recordExistingBehaviorReceipt(testInfo, { channel: 'portal', receipt }, observations);
  }
  return receipt;
}

/** Entries without a matching executed passed result NEVER become evidence. No source-file/test-title inference. */
export function reconcilePortalActionCoverage(coverage, executedResults = []) {
  const executionFailures = executedResults.filter((result) => result.status !== 'passed' || result.retry !== 0).map((result) => ({ testId: result.testId, status: result.status, retry: result.retry, reason: 'Every declared executed result must be terminal passing at zero retries, including tests without receipts.' }));
  const publicResults = executedResults.map((result) => ({ ...result, receipts: (result.receipts ?? []).filter((receipt) => receipt.scope === 'public-auth') }));
  const authenticatedResults = executedResults.map((result) => ({ ...result, receipts: (result.receipts ?? []).filter((receipt) => receipt.scope !== 'public-auth') }));
  const publicAuth = coverage.publicAuth ? reconcilePublicPortalActionCoverage(coverage.publicAuth, publicResults) : null;
  const knownCells = new Map(coverage.cells.filter((cell) => cell.applicable === true).map((cell) => [cell.id, cell]));
  const accepted = new Map();
  const rejected = coverage.publicAuth ? [] : publicResults.flatMap((result) => result.receipts.map((receipt) => ({ cellId: receipt.cellId, reason: 'public-scope-not-inventoried' })));
  const duplicateAssertions = [];
  for (const result of authenticatedResults) for (const receipt of result.receipts ?? []) {
    const known = knownCells.get(receipt.cellId);
    const reason = result.status !== 'passed' ? 'test-not-passed'
      : receipt.schema !== ACTION_RECEIPT_SCHEMA ? 'wrong-schema'
        : result.retry !== 0 || receipt.retry !== 0 ? 'retry-not-zero'
          : receipt.testId !== result.testId ? 'test-identity-mismatch'
            : result.titlePath && JSON.stringify(result.titlePath) !== JSON.stringify(receipt.titlePath) ? 'test-title-mismatch'
              : receipt.sourceDigest !== coverage.sourceDigest ? 'stale-source'
                : !known ? 'unknown-cell'
                  : actionCellId(receipt) !== receipt.cellId || ['action', 'route', 'principal', 'role', 'dataset', 'state', 'channel'].some((field) => (receipt[field] ?? (field === 'channel' ? 'ui' : undefined)) !== known[field]) ? 'cell-dimension-mismatch'
                    : !Array.isArray(receipt.observations) || !receipt.observations.length || receipt.observations.some((item) => typeof item !== 'string' || !item.trim()) ? 'no-behavior-assertions'
                      : typeof receipt.assertionCompletedAt !== 'string' || !Number.isFinite(Date.parse(receipt.assertionCompletedAt)) ? 'assertion-not-completed' : null;
    if (reason) rejected.push({ cellId: receipt.cellId, reason });
    else if (accepted.has(receipt.cellId)) duplicateAssertions.push({ cellId: receipt.cellId, testId: receipt.testId, reason: 'Additional independently passing assertion for the same canonical obligation; retain first evidence, never multiply covered count.' });
    else accepted.set(receipt.cellId, receipt);
  }
  const uncovered = coverage.cells.filter((cell) => cell.applicable === true && !accepted.has(cell.id));
  return { publicAuth, executionFailures, complete: !executionFailures.length && (publicAuth === null || publicAuth.complete) && !rejected.length && !uncovered.length && !coverage.inventory.unresolved.length && !coverage.unmappedSourceActions.length && !coverage.unclassifiedStates.length,
    covered: [...accepted.values()], duplicateAssertions, uncovered, notApplicable: coverage.cells.filter((cell) => cell.applicable === false), rejected,
    unclassifiedStates: coverage.unclassifiedStates,
    unresolvedSourceRoots: coverage.inventory.unresolved, unmappedSourceActions: coverage.unmappedSourceActions };
}

export function assertAllApplicablePortalActionCells(coverage, executedResults) {
  const result = reconcilePortalActionCoverage(coverage, executedResults);
  if (!result.complete) {
    const sample = result.uncovered.slice(0, 12).map((cell) => cell.id).join('\n');
    throw new Error(`Portal action coverage incomplete: ${result.uncovered.length} applicable cells; ${result.unmappedSourceActions.length} unmapped source actions; ${result.unclassifiedStates.length} unclassified state obligations; public/auth ${result.publicAuth ? `${result.publicAuth.uncovered.length} uncovered, ${result.publicAuth.unclassifiedStates.length} unclassified, ${result.publicAuth.rejected.length} invalid receipts` : 'not present in this source fixture'}.\n${sample}`);
  }
  return result;
}
