import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { buildPortalActionInventory } from '../helpers/portal-action-inventory.mjs';
import { NAV_ROUTE_IDS, AUDITOR_NAV_ROUTE_IDS, STAFF_NAV_ROUTE_IDS, DETAIL_ROUTE_IDS, PORTAL_DETAIL_ENTITY_IDS } from '../helpers/portal-routes.mjs';
import { buildPortalRouteHash } from '../helpers/portal-playwright-session.mjs';
import { ACTION_STATES, CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES, actionStateApplicability } from '../fixtures/portal-action-coverage.mjs';
import { buildPortalActionCoverage, reconcilePortalActionCoverage, assertAllApplicablePortalActionCells, ACTION_RECEIPT_SCHEMA, actionPermissionDecision, portalDatasetReadDimensions } from '../helpers/portal-action-coverage.mjs';

let inventory;
const getInventory = () => inventory ??= buildPortalActionInventory();

test('route fixture classification exactly matches shipped navigation including legacy runs with no invented entity', () => {
  const actual = getInventory();
  assert.deepEqual([...NAV_ROUTE_IDS, ...AUDITOR_NAV_ROUTE_IDS, ...STAFF_NAV_ROUTE_IDS].sort(), [...actual.navigation].sort());
  assert.deepEqual([...DETAIL_ROUTE_IDS].sort(), [...actual.details].sort());
  assert.equal(NAV_ROUTE_IDS.includes('runs'), false);
  assert.equal(DETAIL_ROUTE_IDS.includes('runs'), true);
  assert.equal(PORTAL_DETAIL_ENTITY_IDS.runs, undefined);
  assert.equal(buildPortalRouteHash('runs'), 'runs');
  assert.deepEqual(actual.unresolved, []);
});

test('shipped semantic inventory reaches real forms, controls and callbacks, never held reviewed or prototype exports', () => {
  const actual = getInventory();
  assert.ok(actual.actions.some((action) => action.owner === 'ValidationScanLauncher' && action.kind === 'form-keyboard' && action.routes.includes('runs')));
  assert.ok(actual.actions.some((action) => action.owner === 'IntegrationPage' && action.handlers.onSubmit === 'handleCreateConnector' && action.routes.includes('integrations')));
  assert.ok(actual.actions.some((action) => action.owner === 'SettingsPage' && action.routes.includes('settings')));
  for (const kind of ['anchor', 'select', 'checkable', 'field', 'form-keyboard', 'activate', 'action-slot']) {
    assert.ok(actual.actions.some((action) => action.kind === kind), `missing semantic kind ${kind}`);
  }
  assert.equal(actual.actions.some((action) => /reviewed-safe-check|prototype/.test(action.file)), false);
  assert.equal(actual.routes.includes('target-groups'), false);
});

const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-action-ast-'));
after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
function fixture(file, text) { const target = path.join(fixtureRoot, 'apps/web/react/src', file); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, text); }

test('AST follows imported value symbols and excludes dead JSX in the same module', () => {
  fixture('lib/navigation.ts', "export const NAV_ITEMS=[{id:'settings'}]; export const DETAIL_ROUTE_ITEMS=[{id:'runs'}];");
  fixture('pages/router.tsx', "import {SettingsPage} from './settings'; export function RouteView({route}) {if(route==='settings') return <SettingsPage/>; if(route==='runs') return <a href='#settings'>Open settings</a>;}");
  fixture('pages/settings.tsx', "function Picker(){return <select aria-label='Mode' onChange={()=>{}}/>} export function SettingsPage(){return <form onSubmit={()=>{}}><Picker/><input type='checkbox' aria-label='Accept'/><button>Save</button></form>} export function DeadPrototype(){return <button>Never shipped</button>}");
  fixture('components/layout/app-shell.tsx', "export function AppShell(){return <button onClick={()=>{}}>Refresh</button>}");
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  assert.ok(actual.actions.some((action) => action.owner === 'Picker' && action.routes.includes('settings')));
  assert.ok(actual.actions.some((action) => action.owner === 'AppShell' && action.routes.includes('settings') && action.routes.includes('runs')));
  assert.equal(actual.actions.some((action) => action.owner === 'DeadPrototype'), false);
  assert.equal(actual.reachedSymbols.some((symbol) => /DeadPrototype/.test(symbol)), false);
});

test('AST transaction traits resolve actual requests, retain every caller route, and block unknown callbacks instead of declaring N/A', () => {
  fixture('lib/navigation.ts', "export const NAV_ITEMS=[{id:'settings'},{id:'targets'}]; export const DETAIL_ROUTE_ITEMS=[];");
  fixture('pages/router.tsx', "import {SettingsPage} from './settings'; export function RouteView({route}) {if(route==='settings'||route==='targets') return <SettingsPage/>;}");
  fixture('pages/settings.tsx', `export function SettingsPage({onRetry}) {
    const [name,setName]=useState(''); const [busy,setBusy]=useState(false);
    const canSave=sessionHasPermission(session,'tenant:write');
    async function save(event){event.preventDefault();setBusy(true);await requestJson(config,session,'/v1/tenants/current',{method:'PATCH',body:{name}});setBusy(false);}
    return <><input aria-label='Draft' value={name} onChange={event=>setName(event.target.value)}/>{canSave?<form onSubmit={save}><input required/><button disabled={busy}>Save</button></form>:null}<button onClick={()=>onRetry()}>Retry injected action</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const draft = actual.actions.find((action) => action.label === 'Draft');
  const save = actual.actions.find((action) => action.kind === 'form-keyboard');
  const retry = actual.actions.find((action) => action.label === 'Retry injected action');
  assert.deepEqual(save.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/tenants/current', method: 'PATCH' }]);
  assert.deepEqual(save.traits.permissions, ['tenant:write']);
  assert.equal(actionStateApplicability(save).busy.applicable, true);
  assert.equal(actionStateApplicability(save).reload.applicable, true);
  for (const state of ['busy', 'error-retry', 'cancel', 'reload']) assert.equal(actionStateApplicability(draft)[state].applicable, false, `local draft ${state}`);
  assert.equal(actionStateApplicability(retry).busy.applicable, null);
  const coverage = buildPortalActionCoverage({ inventory: actual });
  const formEntries = coverage.semanticFamilies.find((family) => family.id === save.id).entrypoints;
  assert.deepEqual(formEntries.filter((entry) => entry.role === 'owner').map((entry) => entry.route).sort(), ['settings', 'targets']);
  assert.equal(coverage.routeAuthorization.length, 24);
  assert.ok(coverage.unclassifiedStates.length > 0);
  assert.throws(() => assertAllApplicablePortalActionCells(coverage, []), /unclassified state obligations/);
});

test('injected callback binding requires identical actual declaration, keeps ambiguous callers blocking and retains lexical native locals', () => {
  fixture('pages/settings.tsx', `function Leaf({onRefresh,onClose}) { return <><button onClick={onRefresh}>Refresh leaf</button><button onClick={onClose}>Close leaf</button></>; }
    function removeParam(){const kept=new URLSearchParams();kept.delete('x');}
    export function SettingsPage(){ const [tab,setTab]=useState('a'); async function refresh(){await requestJson(config,session,'/v1/targets',{method:'GET'});}
      return <><Leaf onRefresh={refresh} onClose={()=>setTab('a')}/><Leaf onRefresh={()=>void refresh()} onClose={()=>setTab('b')}/><button onClick={removeParam}>Native local</button><input onChange={setTab} aria-label='Direct setter'/></>; }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const refresh = actual.actions.find((action) => action.label === 'Refresh leaf');
  assert.deepEqual(refresh.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/targets', method: 'GET' }]);
  assert.deepEqual(refresh.traits.unresolvedCallbacks, []);
  assert.deepEqual(actual.actions.find((action) => action.label === 'Close leaf').traits.unresolvedCallbacks, ['onClose']);
  assert.deepEqual(actual.actions.find((action) => action.label === 'Native local').traits.unresolvedCallbacks, []);
  assert.deepEqual(actual.actions.find((action) => action.label === 'Direct setter').traits.unresolvedCallbacks, []);
});

test('canonical SOC boundary binds the invoked wrapper path/options instead of inventing generic GET effects', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    function socFetch(path, options){return requestSocJson(config, session, path, options);}
    return <button onClick={()=>socFetch('/internal/soc/requests/request_synthetic/schedule',{method:'POST',body:{}})}>Schedule wrapper</button>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const action = actual.actions.find((item) => item.label === 'Schedule wrapper');
  assert.deepEqual(action.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/internal/soc/requests/request_synthetic/schedule', method: 'POST' }]);
  assert.deepEqual(action.traits.unresolvedCallbacks, []);
  assert.equal(actionStateApplicability(action).reload.applicable, true);
});

test('a callback invoked through a wrapper parameter contributes its exact request, busy and retry obligations', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    const [busy,setBusy]=useState('');
    async function runAction(label, action){ setBusy(label); try { return await action(); } finally { setBusy(''); } }
    async function persist(){ return requestJson(config,session,'/v1/named',{method:'PATCH'}); }
    async function save(event){ event.preventDefault(); await runAction('save', () => requestJson(config,session,'/v1/notifications',{method:'POST',body:{}})); }
    return <><form onSubmit={save} aria-busy={busy==='save'}><button type='submit' disabled={busy!==''}>Save rule</button></form>
      <button onClick={()=>runAction('named', persist)} disabled={busy!==''}>Named wrapper</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const form = actual.actions.find((item) => item.kind === 'form-keyboard');
  assert.deepEqual(form.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/notifications', method: 'POST' }]);
  const states = actionStateApplicability(form);
  assert.equal(states.busy.applicable, true);
  assert.equal(states['error-retry'].applicable, true);
  const named = actual.actions.find((item) => item.label === 'Named wrapper');
  assert.deepEqual(named.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/named', method: 'PATCH' }]);
  assert.deepEqual(named.traits.unresolvedCallbacks, []);
});

test('a navigating non-anchor action with unresolved callbacks stays blocking instead of N/A', () => {
  const states = actionStateApplicability({ kind: 'button', label: 'Refresh', handlers: {}, traits: { requests: [], navigation: true, unresolvedCallbacks: ['onRefresh'] } });
  for (const state of ['busy', 'invalid', 'cancel', 'error-retry', 'denial']) assert.equal(states[state].applicable, null, state);
  const anchor = actionStateApplicability({ kind: 'anchor', label: 'Docs', handlers: {}, traits: { requests: [], navigation: true, unresolvedCallbacks: ['onNavigate'] } });
  assert.equal(anchor.reload.applicable, true);
});

test('unused nested callbacks and shadowed local names cannot introduce phantom requests into a reached action', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    const endpoint='/v1/targets';
    function unused(){const endpoint=requestJson(config,session,'/v1/not-invoked',{method:'POST'});return endpoint;}
    function save(){return requestJson(config,session,endpoint,{method:'GET'});}
    return <button onClick={save}>Read actual</button>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const action = actual.actions.find((item) => item.label === 'Read actual');
  assert.equal(action.traits.requests.some((request) => request.endpointShape === '/v1/not-invoked'), false);
  assert.equal(action.traits.requests.some((request) => request.method === 'POST'), false);
});

test('permission expressions preserve OR alternatives, alternate polarity and owner-only early exits', () => {
  fixture('pages/settings.tsx', `export function SettingsPage() {
    const canSave=sessionHasPermission(session,'tenant:write');
    const canAdd=sessionHasPermission(session,'target_group:write') || sessionHasPermission(session,'waf:connector_write');
    function unrelated(){if(!sessionHasPermission(session,'secret:write'))return null;}
    return <>{canSave?<button onClick={()=>{}}>Allowed save</button>:<button onClick={()=>{}}>Read-only fallback</button>}{canAdd&&<button onClick={()=>{}}>Add connector</button>}<button onClick={()=>{}}>Unrestricted sibling</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const coverage = buildPortalActionCoverage({ inventory: actual });
  const cells = (label, role) => coverage.cells.filter((cell) => cell.action === actual.actions.find((action) => action.label === label).id && cell.role === role && cell.route === 'settings');
  assert.equal(cells('Allowed save', 'engineer').find((cell) => cell.state === 'success').applicable, false);
  assert.equal(cells('Allowed save', 'engineer').find((cell) => cell.state === 'denial').applicable, true);
  assert.equal(cells('Allowed save', 'owner').find((cell) => cell.state === 'denial').applicable, false);
  assert.equal(cells('Read-only fallback', 'engineer').find((cell) => cell.state === 'success').applicable, true);
  assert.equal(cells('Read-only fallback', 'owner').find((cell) => cell.state === 'success').applicable, false);
  assert.equal(cells('Add connector', 'engineer').find((cell) => cell.state === 'success').applicable, true);
  assert.equal(cells('Add connector', 'viewer').find((cell) => cell.state === 'success').applicable, false);
  assert.deepEqual(actual.actions.find((action) => action.label === 'Unrestricted sibling').traits.authorizationGuards, []);
  assert.throws(() => assertAllApplicablePortalActionCells(coverage, []), /coverage incomplete/);
});

test('role, route, dataset and mutation permission dimensions are separate and unknown customer role defers backend', () => {
  assert.deepEqual(CUSTOMER_ACTION_ROLES, ['owner', 'admin', 'engineer', 'soc', 'auditor', 'viewer']);
  assert.deepEqual(STAFF_ACTION_ROLES, ['internal_admin', 'billing_ops', 'support_engineer', 'soc_analyst', 'soc_lead', 'security_admin']);
  const coverage = buildPortalActionCoverage({ inventory: getInventory(), datasets: ['baseline'] });
  const engineer = coverage.dimensions.find((dimension) => dimension.route === 'settings' && dimension.role === 'engineer' && dimension.principal === 'customer');
  assert.equal(engineer.routeAllowed, true);
  assert.equal(actionPermissionDecision(engineer, 'secret:write'), false);
  assert.equal(engineer.datasets.find((dataset) => dataset.dataset === 'secrets').readable, false);
  assert.equal(actionPermissionDecision({ principal: 'customer', session: {} }, 'secret:write'), true);
  assert.equal(actionPermissionDecision({ principal: 'staff', session: { principal: 'staff', staff_role: 'internal_admin' } }, 'secret:write'), false);
  const releaseOwner = portalDatasetReadDimensions().find((dimension) => dimension.datasetId === 'releaseEvidence' && dimension.role === 'owner');
  assert.equal(releaseOwner.readable, true);
  assert.equal(releaseOwner.routeAllowed, false);
  assert.equal(releaseOwner.hydrationAllowed, false);
  const releaseAuditor = portalDatasetReadDimensions().find((dimension) => dimension.datasetId === 'releaseEvidence' && dimension.role === 'auditor');
  assert.equal(releaseAuditor.hydrationAllowed, true);
  assert.deepEqual(new Set(coverage.cells.map((cell) => cell.state)), new Set(ACTION_STATES));
});

test('coverage remains failing until executed passing assertion receipts fill every applicable cell', () => {
  const coverage = buildPortalActionCoverage({ inventory: getInventory(), datasets: ['baseline'] });
  assert.throws(() => assertAllApplicablePortalActionCells(coverage, []), /coverage incomplete/);
  const cell = coverage.cells.find((item) => item.applicable);
  const receipt = { ...cell, schema: ACTION_RECEIPT_SCHEMA, cellId: cell.id, testId: 'executed-test', titlePath: ['suite', 'actual assertion'], retry: 0, sourceDigest: coverage.sourceDigest, assertionCompletedAt: new Date().toISOString(), observations: ['exact request and rendered state asserted'] };
  const executed = { testId: 'executed-test', titlePath: receipt.titlePath, retry: 0, status: 'passed', receipts: [receipt] };
  assert.equal(reconcilePortalActionCoverage(coverage, [{ ...executed, status: 'failed' }]).covered.length, 0);
  assert.equal(reconcilePortalActionCoverage(coverage, [{ ...executed, receipts: [{ ...receipt, sourceDigest: 'stale' }] }]).covered.length, 0);
  for (const forged of [{ role: 'invented' }, { route: 'wrong' }, { action: 'wrong' }, { state: 'wrong' }, { retry: 1 }, { observations: [''] }, { observations: [null] }, { assertionCompletedAt: '' }, { titlePath: ['wrong title'] }]) {
    const rejected = reconcilePortalActionCoverage(coverage, [{ ...executed, receipts: [{ ...receipt, ...forged }] }]);
    assert.equal(rejected.covered.length, 0, `Forged receipt must not cover a cell: ${JSON.stringify(forged)}`);
    assert.equal(rejected.rejected.length, 1);
  }
  assert.equal(reconcilePortalActionCoverage(coverage, [{ ...executed, retry: 1 }]).covered.length, 0);
  const result = reconcilePortalActionCoverage(coverage, [executed]);
  assert.equal(result.covered.length, 1);
  assert.equal(result.complete, false);
  assert.ok(result.uncovered.length > 0);
  assert.ok(result.notApplicable.every((item) => item.reason));
  const oneCellCoverage = { ...coverage, publicAuth: null, cells: [cell], unclassifiedStates: [], unmappedSourceActions: [], inventory: { ...coverage.inventory, unresolved: [] } };
  assert.equal(reconcilePortalActionCoverage(oneCellCoverage, [executed]).complete, true);
  const pendingPublic = { schema: 'portal-public-coverage/v1', sourceDigest: 'public-independent', inventory: { unresolved: [] }, cells: [{ id: 'public-obligation', applicable: true }], unclassifiedStates: [], unmappedSourceActions: [] };
  const combined = reconcilePortalActionCoverage({ ...oneCellCoverage, publicAuth: pendingPublic }, [executed]);
  assert.equal(combined.covered.length, 1);
  assert.equal(combined.publicAuth.uncovered.length, 1);
  assert.equal(combined.complete, false, 'Authentication-only proof cannot satisfy the separate visitor/public/auth gate');
  for (const terminal of ['failed', 'skipped', 'interrupted']) assert.equal(reconcilePortalActionCoverage(oneCellCoverage, [executed, { testId: 'unreceipted-extra', status: terminal, retry: 0, receipts: [] }]).complete, false);
  assert.equal(reconcilePortalActionCoverage(oneCellCoverage, [executed, { testId: 'retried-extra', status: 'passed', retry: 1, receipts: [] }]).complete, false);
  const withInvalidExtra = reconcilePortalActionCoverage(oneCellCoverage, [{ ...executed, receipts: [receipt, { ...receipt, sourceDigest: 'stale' }] }]);
  assert.equal(withInvalidExtra.complete, false);
  assert.equal(withInvalidExtra.rejected.length, 1);
  const duplicates = reconcilePortalActionCoverage(oneCellCoverage, [{ ...executed, receipts: [receipt, receipt] }]);
  assert.equal(duplicates.complete, true);
  assert.equal(duplicates.covered.length, 1);
  assert.equal(duplicates.duplicateAssertions.length, 1);
});
