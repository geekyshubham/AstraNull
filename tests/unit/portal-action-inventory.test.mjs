import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { buildPortalActionInventory } from '../helpers/portal-action-inventory.mjs';
import { NAV_ROUTE_IDS, AUDITOR_NAV_ROUTE_IDS, STAFF_NAV_ROUTE_IDS, DETAIL_ROUTE_IDS, PORTAL_DETAIL_ENTITY_IDS } from '../helpers/portal-routes.mjs';
import { buildPortalRouteHash } from '../helpers/portal-playwright-session.mjs';
import { ACTION_STATES, CUSTOMER_ACTION_ROLES, STAFF_ACTION_ROLES, actionStateApplicability } from '../fixtures/portal-action-coverage.mjs';
import { buildPortalActionCoverage, reconcilePortalActionCoverage, assertAllApplicablePortalActionCells, ACTION_RECEIPT_SCHEMA, actionPermissionDecision, portalDatasetReadDimensions, unmappedPortalDatasets, API_ONLY_DATASETS } from '../helpers/portal-action-coverage.mjs';
import { PORTAL_ROUTE_DATASETS } from '../../apps/web/react/src/lib/types.ts';

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

test('object-destructured callbacks bind only actual property invocations including aliases, forwarding and defaults', () => {
  fixture('lib/navigation.ts', "export const NAV_ITEMS=[{id:'settings'}]; export const DETAIL_ROUTE_ITEMS=[];");
  fixture('pages/router.tsx', "import {SettingsPage} from './settings'; export function RouteView({route}) {if(route==='settings') return <SettingsPage/>;}");
  fixture('components/layout/app-shell.tsx', 'export function AppShell(){return null;}');
  fixture('pages/settings.tsx', `export function SettingsPage(){
    const [busy,setBusy]=useState(false);const [value,setValue]=useState(null);
    async function lifecycle({load: read,onCommit,onError,onSettled=()=>{}}){setBusy(true);try{onCommit(await read());}catch(error){onError(error);}finally{onSettled();}}
    function forward(load){return lifecycle({load,onCommit:value=>setValue(value),onError:()=>setValue(null),onSettled:()=>setBusy(false)});}
    function save(){return forward(()=>requestJson(config,session,'/v1/lifecycle',{method:'POST'}));}
    function defaults(){return lifecycle({load:()=>requestJson(config,session,'/v1/default',{method:'GET'}),onCommit:()=>{},onError:()=>{}});}
    return <><button onClick={save} disabled={busy}>Object lifecycle</button><button onClick={defaults}>Default callback</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const action = actual.actions.find((item) => item.label === 'Object lifecycle');
  assert.deepEqual(action.traits.requests.map(({endpointShape,method}) => ({endpointShape,method})), [{endpointShape:'/v1/lifecycle',method:'POST'}]);
  assert.deepEqual(action.traits.unresolvedCallbacks, []);
  assert.equal(actionStateApplicability(action).busy.applicable, true);
  assert.equal(actionStateApplicability(action).reload.applicable, true);
  const defaults = actual.actions.find((item) => item.label === 'Default callback');
  assert.deepEqual(defaults.traits.unresolvedCallbacks, []);
  assert.deepEqual(defaults.traits.requests.map(({endpointShape,method}) => ({endpointShape,method})), [{endpointShape:'/v1/default',method:'GET'}]);
});

test('object-destructured callbacks keep opaque, spread-overridden and shadowed bindings unresolved', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({opaque,onCommit}){
    function lifecycle({load,onCommit,onSettled}){load();onCommit();onSettled?.();}
    function unknown(){return lifecycle(opaque);}
    function spread(){return lifecycle({load:()=>requestJson(config,session,'/v1/overridden',{method:'POST'}),onCommit:()=>{},...opaque});}
    function injected(){return lifecycle({load:()=>{},onCommit});}
    function shadow(){return lifecycle({load:onCommit,onCommit:()=>{}});}
    return <><button onClick={unknown}>Opaque lifecycle</button><button onClick={spread}>Spread lifecycle</button><button onClick={injected}>Injected lifecycle</button><button onClick={shadow}>Shadowed lifecycle</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  for (const label of ['Opaque lifecycle','Spread lifecycle','Injected lifecycle','Shadowed lifecycle']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.ok(action.traits.unresolvedCallbacks.length, label);
    assert.equal(actionStateApplicability(action).reload.applicable, null, label);
    assert.equal(action.traits.requests.some((request) => request.endpointShape === '/v1/overridden'), false, label);
  }
});

test('object-destructured callbacks reject accessors, computed keys and reassigned parameters; duplicate properties use the last value', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({opaque}){
    function lifecycle({load}){load();}
    function reassigned({load}){load=opaque;load();}
    function duplicate(){return lifecycle({load:()=>requestJson(config,session,'/v1/first',{method:'POST'}),load:()=>requestJson(config,session,'/v1/last',{method:'GET'})});}
    return <><button onClick={duplicate}>Duplicate callback</button><button onClick={()=>lifecycle({get load(){return opaque}})}>Getter callback</button><button onClick={()=>lifecycle({['load']:opaque})}>Computed callback</button><button onClick={()=>reassigned({load:()=>requestJson(config,session,'/v1/replaced',{method:'POST'})})}>Reassigned callback</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const duplicate = actual.actions.find((item) => item.label === 'Duplicate callback');
  assert.deepEqual(duplicate.traits.requests.map(({endpointShape,method}) => ({endpointShape,method})), [{endpointShape:'/v1/last',method:'GET'}]);
  assert.deepEqual(duplicate.traits.unresolvedCallbacks, []);
  for (const label of ['Getter callback','Computed callback','Reassigned callback']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.ok(action.traits.unresolvedCallbacks.length, label);
    assert.equal(action.traits.requests.some((request) => request.endpointShape === '/v1/replaced'), false, label);
  }
});

test('object-destructured callback defaults require known absence, missing callbacks do not borrow captured names, and arguments forward exactly', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({opaque}){
    function optional({onSettled}){onSettled?.();}
    function required({load}){load();}
    function defaults({load=()=>requestJson(config,session,'/v1/fallback',{method:'GET'})}){load();}
    function lifecycle({load,onCommit}){onCommit(load);}
    function wrap(load){return lifecycle({load,onCommit:(load)=>{function omitted(load){load();}omitted();}});}
    return <><button onClick={()=>optional({})}>Absent optional</button><button onClick={()=>required({})}>Absent required</button><button onClick={()=>defaults(opaque)}>Opaque default</button><button onClick={()=>wrap(()=>requestJson(config,session,'/v1/borrowed',{method:'POST'}))}>Captured name shadow</button><button onClick={()=>lifecycle({load:()=>requestJson(config,session,'/v1/forwarded',{method:'PATCH'}),onCommit:read=>read()})}>Forward argument</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  assert.deepEqual(actual.actions.find((item) => item.label === 'Absent optional').traits.unresolvedCallbacks, []);
  for (const label of ['Absent required','Opaque default','Captured name shadow']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.ok(action.traits.unresolvedCallbacks.length, label);
    assert.deepEqual(action.traits.requests, [], label);
  }
  const forwarded = actual.actions.find((item) => item.label === 'Forward argument');
  assert.deepEqual(forwarded.traits.unresolvedCallbacks, []);
  assert.deepEqual(forwarded.traits.requests.map(({endpointShape,method}) => ({endpointShape,method})), [{endpointShape:'/v1/forwarded',method:'PATCH'}]);
});

test('object-destructured callback objects resolve lexical aliases but never replay mutated objects', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({opaque}){
    function lifecycle({load}){load();}
    function alias(){const callbacks={load:()=>requestJson(config,session,'/v1/alias',{method:'GET'})};const forwarded=callbacks;return lifecycle(forwarded);}
    function mutated(){const changed={load:()=>requestJson(config,session,'/v1/stale',{method:'POST'})};changed.load=opaque;return lifecycle(changed);}
    function aliasMutation(){const original={load:()=>requestJson(config,session,'/v1/stale-alias',{method:'POST'})};const changedAlias=original;changedAlias.load=opaque;return lifecycle(original);}
    return <><button onClick={alias}>Aliased object</button><button onClick={mutated}>Mutated object</button><button onClick={aliasMutation}>Mutated alias</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const alias = actual.actions.find((item) => item.label === 'Aliased object');
  assert.deepEqual(alias.traits.unresolvedCallbacks, []);
  assert.deepEqual(alias.traits.requests.map(({endpointShape,method}) => ({endpointShape,method})), [{endpointShape:'/v1/alias',method:'GET'}]);
  for (const label of ['Mutated object','Mutated alias']) {
    const mutated = actual.actions.find((item) => item.label === label);
    assert.ok(mutated.traits.unresolvedCallbacks.length, label);
    assert.deepEqual(mutated.traits.requests, [], label);
  }
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

test('reading a closure value never replays its initializer, while invoking a retained callback retains its request', () => {
  fixture('pages/settings.tsx', `import {useCallback} from 'react';
    export function SettingsPage(){
      const snapshot=requestJson(config,session,'/v1/render-only',{method:'POST'});
      const [label,setLabel]=useState('');
      const refresh=useCallback(()=>requestJson(config,session,'/v1/refresh-only',{method:'GET'}),[]);
      return <><button onClick={()=>setLabel(snapshot.status)}>Read existing snapshot</button><button onClick={refresh}>Invoke retained refresh</button></>;
    }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const read = actual.actions.find((action) => action.label === 'Read existing snapshot');
  assert.deepEqual(read.traits.requests, []);
  assert.equal(read.traits.localChange, true);
  const refresh = actual.actions.find((action) => action.label === 'Invoke retained refresh');
  assert.deepEqual(refresh.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/refresh-only', method: 'GET' }]);
});

test('helper-local collection bindings resolve without suppressing an unresolved business callback', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({onRunSelectionChange}) {
    function changeSelection(){const next=new Set(['first']);next.delete('first');onRunSelectionChange([...next]);}
    return <button onClick={changeSelection}>Change selection</button>;
  }`);
  const action = buildPortalActionInventory({ root: fixtureRoot }).actions.find((item) => item.label === 'Change selection');
  assert.deepEqual(action.traits.requests, []);
  assert.deepEqual(action.traits.unresolvedCallbacks, ['onRunSelectionChange']);
  assert.equal(actionStateApplicability(action).reload.applicable, null);
});

test('native collection returned by an exact helper remains local, unlike an opaque or asynchronous factory', () => {
  fixture('pages/settings.tsx', `function params(input){const kept=new URLSearchParams(input);kept.set('mode','safe');return kept;}
    async function asyncParams(){return new URLSearchParams();}
    export function SettingsPage(){
      function local(){const kept=params('');kept.delete('mode');}
      function opaque(){const kept=opaqueFactory();kept.delete('mode');}
      function asynchronous(){const kept=asyncParams();kept.delete('mode');}
      return <><button onClick={local}>Returned native collection</button><button onClick={opaque}>Opaque collection</button><button onClick={asynchronous}>Async collection</button></>;
    }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  assert.deepEqual(actual.actions.find((item) => item.label === 'Returned native collection').traits.unresolvedCallbacks, []);
  for (const label of ['Opaque collection', 'Async collection']) assert.ok(actual.actions.find((item) => item.label === label).traits.unresolvedCallbacks.includes('kept.delete'), label);
});

test('returned callbacks and unshadowed builtin aliases resolve but opaque factories and aliases remain blocking', () => {
  fixture('pages/settings.tsx', `import {useCallback} from 'react';
    function createKey(){const prefix='key';return ()=>JSON.stringify([prefix]);}
    function useOpen(){return useCallback((path)=>requestJson(config,session,path,{method:'GET'}),[]);}
    export function SettingsPage({injected}) {
      const key=createKey();const open=useOpen();const enc=encodeURIComponent;const unknown=injected;const opaque=unknownFactory();
      return <><button onClick={()=>key()}>Pure returned callback</button><button onClick={()=>open('/v1/returned')}>Returned request callback</button><button onClick={()=>enc('value')}>Builtin alias</button><button onClick={()=>unknown()}>Unknown alias</button><button onClick={()=>opaque()}>Opaque factory</button></>;
    }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  for (const label of ['Pure returned callback', 'Builtin alias']) assert.deepEqual(actual.actions.find((action) => action.label === label).traits.unresolvedCallbacks, [], label);
  const open = actual.actions.find((action) => action.label === 'Returned request callback');
  assert.deepEqual(open.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/returned', method: 'GET' }]);
  assert.deepEqual(open.traits.unresolvedCallbacks, []);
  for (const label of ['Unknown alias', 'Opaque factory']) assert.ok(actual.actions.find((action) => action.label === label).traits.unresolvedCallbacks.length, label);
});

test('shadowed builtin aliases and ambiguous returned callbacks never become proven local behavior', () => {
  fixture('pages/settings.tsx', `import {decodeURIComponent} from 'opaque-package';
    function choose(flag){if(flag)return ()=>requestJson(config,session,'/v1/one',{method:'POST'});return ()=>requestJson(config,session,'/v1/two',{method:'POST'});}
    export function SettingsPage({encodeURIComponent}) {
      const enc=encodeURIComponent;const dec=decodeURIComponent;const ambiguous=choose();
      return <><button onClick={()=>enc('x')}>Shadowed parameter alias</button><button onClick={()=>dec('x')}>External import alias</button><button onClick={()=>ambiguous()}>Ambiguous factory</button></>;
    }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  for (const label of ['Shadowed parameter alias', 'External import alias', 'Ambiguous factory']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.ok(action.traits.unresolvedCallbacks.length, label);
    assert.equal(actionStateApplicability(action).reload.applicable, null, label);
  }
});

test('member callback invocation resolves exact object properties while an opaque retained reader remains blocking', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    const reader=opaqueReader();
    const callbacks={refresh:(path)=>requestJson(config,session,path,{method:'GET'})};
    return <><button onClick={()=>reader.refresh()}>Opaque reader refresh</button><button onClick={()=>callbacks.refresh('/v1/member')}>Exact member refresh</button><button onClick={callbacks.refresh}>Direct member refresh</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const unknown = actual.actions.find((item) => item.label === 'Opaque reader refresh');
  assert.deepEqual(unknown.traits.requests, []);
  assert.deepEqual(unknown.traits.unresolvedCallbacks, ['reader.refresh']);
  assert.equal(actionStateApplicability(unknown).reload.applicable, null);
  const exact = actual.actions.find((item) => item.label === 'Exact member refresh');
  assert.deepEqual(exact.traits.requests.map(({ endpointShape, method }) => ({ endpointShape, method })), [{ endpointShape: '/v1/member', method: 'GET' }]);
  assert.deepEqual(exact.traits.unresolvedCallbacks, []);
  assert.ok(actual.actions.find((item) => item.label === 'Direct member refresh').traits.requests.length);
});

test('a reassigned object callback and a helper parameter shadow cannot borrow unrelated declarations', () => {
  fixture('pages/settings.tsx', `function send(){return requestJson(config,session,'/v1/not-the-parameter',{method:'POST'});}
    export function SettingsPage(){
      const callbacks={refresh:()=>{}};callbacks.refresh=externalRefresh;
      function invoke(send){return send();}
      return <><button onClick={()=>callbacks.refresh()}>Reassigned member</button><button onClick={()=>invoke(externalSend)}>Shadowed helper parameter</button></>;
    }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  for (const label of ['Reassigned member', 'Shadowed helper parameter']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.ok(action.traits.unresolvedCallbacks.length, label);
    assert.equal(action.traits.requests.some((request) => request.endpointShape === '/v1/not-the-parameter'), false);
    assert.equal(actionStateApplicability(action).reload.applicable, null, label);
  }
});

test('post-request refresh permissions are provenance, not eligibility for an already completed mutation', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    function routeAllowed(){return staffSessionHasPermission(session,'staff:tenant:read');}
    function refresh(){if(!routeAllowed())return;return requestJson(config,session,'/v1/refreshed',{method:'GET'});}
    async function save(){await requestJson(config,session,'/v1/saved',{method:'POST'});refresh();if(staffSessionHasPermission(session,'soc:high_scale'))setMessage('staff');}
    return <button onClick={save}>Save then refresh</button>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const action = actual.actions.find((item) => item.label === 'Save then refresh');
  assert.deepEqual(action.traits.permissions, []);
  assert.deepEqual(action.traits.authorizationGuards, []);
  assert.equal(action.traits.authorizationUnresolved, false);
  assert.deepEqual([...action.traits.referencedPermissions].sort(), ['soc:high_scale', 'staff:tenant:read']);
  assert.ok(action.traits.requests.some((request) => request.endpointShape === '/v1/saved' && request.method === 'POST'));
  const coverage = buildPortalActionCoverage({ inventory: actual });
  assert.equal(coverage.cells.find((cell) => cell.action === action.id && cell.role === 'owner' && cell.route === 'settings' && cell.state === 'reload').applicable, true);
});

test('an indirect earlier request is ordered before refresh, but conditional request paths keep authorization uncertainty', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({flag}){
    function persist(){return requestJson(config,session,'/v1/persist',{method:'POST'});}
    function refresh(){if(!staffSessionHasPermission(session,'staff:tenant:read'))return;return requestJson(config,session,'/v1/refreshed',{method:'GET'});}
    async function ordered(){await persist();refresh();}
    async function conditional(){if(flag)await persist();refresh();}
    return <><button onClick={ordered}>Ordered helper refresh</button><button onClick={conditional}>Conditional helper refresh</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const ordered = actual.actions.find((action) => action.label === 'Ordered helper refresh');
  assert.deepEqual(ordered.traits.permissions, []);
  assert.equal(ordered.traits.authorizationUnresolved, false);
  const conditional = actual.actions.find((action) => action.label === 'Conditional helper refresh');
  assert.ok(conditional.traits.permissions.includes('staff:tenant:read'));
  assert.equal(conditional.traits.authorizationUnresolved, true);
  assert.deepEqual(conditional.traits.authorizationGuards, [], 'A guard reached on mixed pre/post-request paths is not blanket action eligibility.');
});

test('pre-request helper permission guards remain authoritative and partial unresolved eligibility stays blocking', () => {
  fixture('pages/settings.tsx', `export function SettingsPage(){
    function persist(){if(!sessionHasPermission(session,'tenant:write'))return;return requestJson(config,session,'/v1/guarded',{method:'PATCH'});}
    function opaquePermission(){return Boolean(sessionHasPermission(session,'secret:write'));}
    function partial(){if(!sessionHasPermission(session,'tenant:write'))return;if(!opaquePermission())return;return requestJson(config,session,'/v1/partial',{method:'POST'});}
    return <><button onClick={()=>persist()}>Guarded persist</button><button onClick={partial}>Partially resolved guard</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const guarded = actual.actions.find((action) => action.label === 'Guarded persist');
  assert.deepEqual(guarded.traits.permissions, ['tenant:write']);
  assert.equal(guarded.traits.authorizationUnresolved, false);
  const partial = actual.actions.find((action) => action.label === 'Partially resolved guard');
  assert.equal(partial.traits.authorizationUnresolved, true);
  const coverage = buildPortalActionCoverage({ inventory: actual });
  const cell = (action, role, state) => coverage.cells.find((item) => item.action === action.id && item.route === 'settings' && item.role === role && item.state === state);
  assert.equal(cell(guarded, 'owner', 'reload').applicable, true);
  assert.equal(cell(guarded, 'viewer', 'reload').applicable, false);
  assert.equal(cell(guarded, 'viewer', 'denial').applicable, true);
  assert.equal(cell(partial, 'owner', 'reload').applicable, null);
  assert.equal(cell(partial, 'owner', 'denial').applicable, null);
  assert.equal(cell(partial, 'viewer', 'denial').applicable, true);
});

test('an early exit combining non-authorization limits with a resolved permission preserves its inverted eligibility', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({pending,valid}){
    const canWrite=sessionHasPermission(session,'tenant:write');
    function save(){if(pending || !canWrite || !valid)return;return requestJson(config,session,'/v1/combined',{method:'POST'});}
    return <button onClick={save}>Combined early exit</button>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const action = actual.actions.find((item) => item.label === 'Combined early exit');
  assert.equal(action.traits.authorizationUnresolved, false);
  const coverage = buildPortalActionCoverage({ inventory: actual });
  assert.equal(coverage.cells.find((cell) => cell.action === action.id && cell.route === 'settings' && cell.role === 'owner' && cell.state === 'reload').applicable, true);
  assert.equal(coverage.cells.find((cell) => cell.action === action.id && cell.route === 'settings' && cell.role === 'viewer' && cell.state === 'denial').applicable, true);
});

test('a known permission cannot excuse an unresolved same-permission expression or a dynamic permission guard', () => {
  fixture('pages/settings.tsx', `export function SettingsPage({permissionName}){
    function opaque(){return Boolean(sessionHasPermission(session,'tenant:write'));}
    function save(){if(!sessionHasPermission(session,'tenant:write'))return;if(!opaque())return;return requestJson(config,session,'/v1/opaque',{method:'POST'});}
    function dynamic(){if(!sessionHasPermission(session,permissionName))return;return requestJson(config,session,'/v1/dynamic',{method:'POST'});}
    return <><button onClick={save}>Opaque same-permission guard</button><button onClick={dynamic}>Dynamic permission guard</button></>;
  }`);
  const actual = buildPortalActionInventory({ root: fixtureRoot });
  const coverage = buildPortalActionCoverage({ inventory: actual });
  for (const label of ['Opaque same-permission guard', 'Dynamic permission guard']) {
    const action = actual.actions.find((item) => item.label === label);
    assert.equal(action.traits.authorizationUnresolved, true, label);
    for (const state of ['success', 'denial', 'reload']) assert.equal(coverage.cells.find((cell) => cell.action === action.id && cell.route === 'settings' && cell.role === 'owner' && cell.state === state).applicable, null, `${label}: ${state}`);
  }
});

test('shipped scan confirmation retains its original identity and four request states without downstream route authorization poisoning', () => {
  const actual = getInventory();
  const confirmation = actual.actions.find((action) => action.id === 'apps/web/react/src/components/runs/validation-scan-launcher.tsx#ValidationScanLauncher:action-slot:64509adb68ff');
  assert.ok(confirmation);
  assert.equal(confirmation.traits.authorizationUnresolved, false);
  assert.equal(confirmation.traits.permissions.includes('staff:tenant:read'), false);
  assert.equal(confirmation.traits.permissions.includes('soc:high_scale'), false);
  const coverage = buildPortalActionCoverage({ inventory: actual, publicAuth: null });
  for (const state of ['cancel', 'busy', 'error-retry', 'reload']) {
    const cell = coverage.cells.find((item) => item.action === confirmation.id && item.route === 'runs' && item.principal === 'customer' && item.role === 'owner' && item.dataset === 'baseline' && item.state === state);
    assert.equal(cell.applicable, true, state);
  }
  assert.ok(coverage.unclassifiedStates.length, 'Other unresolved callback/authorization obligations remain blocking.');
  assert.equal(reconcilePortalActionCoverage(coverage, []).complete, false, 'Classification is not executed behavioral evidence.');
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
  assert.deepEqual([...API_ONLY_DATASETS], ['releaseEvidence', 'releaseAttestation']);
  assert.equal(portalDatasetReadDimensions().some((dimension) => API_ONLY_DATASETS.includes(dimension.datasetId)), false);
  assert.equal(Object.values(PORTAL_ROUTE_DATASETS).some((datasets) => datasets.some((dataset) => API_ONLY_DATASETS.includes(dataset))), false);
  assert.deepEqual(unmappedPortalDatasets(), []);
  assert.deepEqual(unmappedPortalDatasets([{ audit: 'audit:read', futureDataset: 'future:read' }]), ['futureDataset']);
  assert.ok(portalDatasetReadDimensions().every((dimension) => typeof dimension.route === 'string' && dimension.route.length > 0));
  const auditOwner = portalDatasetReadDimensions().find((dimension) => dimension.datasetId === 'audit' && dimension.role === 'owner');
  assert.equal(auditOwner.hydrationAllowed, true);
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
