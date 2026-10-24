import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { buildPortalActionInventory } from '../helpers/portal-action-inventory.mjs';
import { actionStateApplicability } from '../fixtures/portal-action-coverage.mjs';
import { actionEligibilityDecision, buildPortalActionCoverage } from '../helpers/portal-action-coverage.mjs';

const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-action-classification-'));
after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
function fixture(file, text) {
  const target = path.join(fixtureRoot, 'apps/web/react/src', file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}
function mount({ shell = 'export function AppShell(){return null}', router, files = {}, navigation = "export const NAV_ITEMS=[{id:'settings'}]; export const DETAIL_ROUTE_ITEMS=[];" }) {
  fixture('lib/navigation.ts', navigation);
  fixture('components/layout/app-shell.tsx', shell);
  fixture('pages/router.tsx', router ?? "import {Page} from './page'; export function RouteView({route}){if(route==='settings') return <Page/>;}");
  for (const [file, text] of Object.entries(files)) fixture(file, text);
  return buildPortalActionInventory({ root: fixtureRoot });
}
const byLabel = (inventory, label) => inventory.actions.find((action) => action.label === label);

test('a conditional callback with an absent branch resolves to the supplied branch and ignores callers that omit it', () => {
  const inventory = mount({
    files: {
      'pages/page.tsx': `function Row({onView}){return <>{onView ? <button onClick={() => onView('a')}>View row</button> : null}</>}
        export function Page({mode}){
          const [open,setOpen]=useState('');
          const view=(id)=>setOpen(id);
          return <><Row/><Row onView={mode==='x' ? view : undefined}/><Row onView={mode==='y' ? null : view}/></>;
        }`,
    },
  });
  const action = byLabel(inventory, 'View row');
  assert.deepEqual(action.traits.unresolvedCallbacks, []);
  assert.equal(action.traits.localChange, true);
});

test('a conditional callback with two real branches or a spreading caller stays blocking', () => {
  const inventory = mount({
    files: {
      'pages/page.tsx': `function Row({onView}){return <>{onView ? <button onClick={() => onView('a')}>View row</button> : null}</>}
        function Other({onView}){return <>{onView ? <button onClick={() => onView('b')}>View other</button> : null}</>}
        export function Page({mode,extra}){
          const first=()=>{}; const second=()=>{};
          return <><Row onView={mode ? first : second}/><Other {...extra} onView={first}/></>;
        }`,
    },
  });
  assert.ok(byLabel(inventory, 'View row').traits.unresolvedCallbacks.length);
  assert.ok(byLabel(inventory, 'View other').traits.unresolvedCallbacks.length);
});

test('a control gated on an optional prop that no mounted caller supplies is an explicit exclusion, never shipped coverage', () => {
  const shell = `export function AppShell({notice='',onDismiss,onKeep}){return <>{notice ? <div>{onDismiss ? <button onClick={onDismiss}>Dismiss</button> : null}{onKeep ? <button onClick={onKeep}>Keep</button> : null}</div> : null}</>}`;
  const router = "import {Page} from './page'; export function RouteView({route}){if(route==='settings') return <Page/>;}";
  fixture('App.tsx', "import {AppShell} from './components/layout/app-shell'; export default function App(){const keep=()=>{};return <AppShell notice='Heads up' onKeep={keep}/>}");
  const inventory = mount({ shell, router, files: { 'pages/page.tsx': 'export function Page(){return <a href="#settings">Settings</a>}' } });
  const dismiss = inventory.excludedActions.find((action) => action.label === 'Dismiss');
  assert.match(dismiss.reason, /optional prop onDismiss/);
  assert.equal(byLabel(inventory, 'Dismiss'), undefined);
  assert.ok(byLabel(inventory, 'Keep'));
  fixture('App.tsx', "import {AppShell} from './components/layout/app-shell'; export default function App(props){return <AppShell {...props} notice='Heads up' onKeep={()=>{}}/>}");
  const spreading = buildPortalActionInventory({ root: fixtureRoot });
  assert.ok(byLabel(spreading, 'Dismiss'));
  fs.rmSync(path.join(fixtureRoot, 'apps/web/react/src/App.tsx'));
});

test('permission calls inside the route-access policy are route authorization, not action eligibility', () => {
  const files = {
    'lib/route-access.ts': "export function roleHasPermission(role,permission){return role==='owner'} export function canAccessRoute(role,route){return roleHasPermission(role,'audit:read')}",
    'pages/page.tsx': `import {canAccessRoute} from '../lib/route-access';
      export function Page({session}){
        function open(){ window.location.hash = canAccessRoute(session.role,'audit') ? 'audit' : 'home'; }
        function save(){ return sessionHasPermission(session,'tenant:write') && requestJson(config,session,'/v1/tenants/current',{method:'PATCH'}); }
        return <><button onClick={open}>Open audit</button><button onClick={save}>Save tenant</button></>;
      }`,
  };
  const inventory = mount({ files });
  const open = byLabel(inventory, 'Open audit');
  assert.deepEqual(open.traits.permissions, []);
  assert.deepEqual(open.traits.referencedPermissions, []);
  assert.equal(open.traits.authorizationUnresolved, false);
  assert.equal(actionStateApplicability(open).denial.applicable, false);
  const save = byLabel(inventory, 'Save tenant');
  assert.deepEqual(save.traits.permissions, ['tenant:write']);
});

test('a shared primitive forwarding a prop is delegated only when every mounted caller binds a resolved callback', () => {
  const primitive = 'export function Button({onClick,children}){return <button onClick={onClick}>{children}</button>}';
  const inventory = mount({
    files: {
      'components/ui/button.tsx': primitive,
      'pages/page.tsx': `import {Button} from '../components/ui/button';
        export function Page(){ const [n,setN]=useState(0); return <><Button onClick={()=>setN(n+1)}>Count</Button><Button onClick={()=>setN(0)}>Reset</Button></>; }`,
    },
  });
  const forwarded = inventory.actions.find((action) => action.owner === 'Button');
  assert.deepEqual(forwarded.traits.unresolvedCallbacks, ['onClick']);
  assert.deepEqual(forwarded.traits.callerBindings, { onClick: { callers: 2, resolved: 2 } });
  const states = actionStateApplicability(forwarded);
  assert.equal(states.success.applicable, true);
  for (const state of ['busy', 'invalid', 'cancel', 'error-retry', 'denial', 'reload']) {
    assert.equal(states[state].applicable, false, state);
    assert.match(states[state].reason, /all 2 supplying mounted callers.*owns the/);
  }
  const opaque = mount({
    router: "import {Page} from './page'; export function RouteView({route,handlers}){if(route==='settings') return <Page onOpaque={handlers.open}/>;}",
    files: {
      'components/ui/button.tsx': primitive,
      'pages/page.tsx': `import {Button} from '../components/ui/button';
        export function Page({onOpaque}){ return <><Button onClick={()=>{}}>Known</Button><Button onClick={onOpaque}>Unknown</Button></>; }`,
    },
  });
  const blocking = opaque.actions.find((action) => action.owner === 'Button');
  assert.deepEqual(blocking.traits.callerBindings, { onClick: { callers: 2, resolved: 1 } });
  assert.equal(actionStateApplicability(blocking).reload.applicable, null);
  const notDelegating = mount({
    files: {
      'pages/page.tsx': `function Leaf({onClick}){return <button onClick={onClick}>Leaf</button>}
        export function Page(){ return <><Leaf onClick={()=>{}}/><Leaf onClick={()=>{}}/></>; }`,
    },
  });
  assert.equal(actionStateApplicability(byLabel(notDelegating, 'Leaf')).reload.applicable, null, 'Only declared shared primitives delegate');
});

test('principal predicates, if-statement gates, forwarded boolean props and role-list helpers become exact eligibility guards', () => {
  const inventory = mount({
    files: {
      'lib/permissions.mjs': "export const START_ROLES = Object.freeze(['owner','engineer']); export function canStart(role){return START_ROLES.includes(String(role ?? '').trim().toLowerCase())}",
      'pages/page.tsx': `import {canStart} from '../lib/permissions.mjs';
        function Switcher({visible}){ return <>{visible ? <select aria-label='Role switcher' onChange={()=>{}}/> : null}</>; }
        export function Page({session}){
          const allowed = canStart(session.role) && session.ready;
          const actions=[];
          if (allowed) actions.push(<a key='x' href='#settings'>Re-test</a>);
          return <><Switcher visible={config.mode==='dev' && session.principal !== 'staff'}/>{actions}</>;
        }`,
    },
  });
  const customer = { principal: 'customer', role: 'owner', session: { role: 'owner' } };
  const viewer = { principal: 'customer', role: 'viewer', session: { role: 'viewer' } };
  const staff = { principal: 'staff', role: 'internal_admin', session: { principal: 'staff', staff_role: 'internal_admin' } };
  const switcher = byLabel(inventory, 'Role switcher');
  assert.deepEqual(switcher.traits.authorizationGuards, [{ principals: ['staff'], invert: true }]);
  assert.equal(actionEligibilityDecision(customer, switcher.traits.authorizationGuards), true);
  assert.equal(actionEligibilityDecision(staff, switcher.traits.authorizationGuards), false);
  const retest = byLabel(inventory, 'Re-test');
  assert.deepEqual(retest.traits.authorizationGuards, [{ roles: ['owner', 'engineer'], principal: 'customer', invert: false }]);
  assert.equal(retest.traits.authorizationUnresolved, false);
  assert.equal(actionEligibilityDecision(customer, retest.traits.authorizationGuards), true);
  assert.equal(actionEligibilityDecision(viewer, retest.traits.authorizationGuards), false);
  assert.equal(actionEligibilityDecision(staff, retest.traits.authorizationGuards), false);
  const states = actionStateApplicability(retest);
  assert.equal(states.denial.applicable, true);
});

test('a component that returns early for staff contributes its resolved principal guard at the callsite', () => {
  const callsite = mount({
    files: {
      'pages/page.tsx': `import {AskButton} from './assist';
        export function Page({session}){ return <AskButton session={session}/>; }`,
      'pages/assist.tsx': `export function AskButton({session}){
        if (session.principal === 'staff') return null;
        return <button onClick={()=>openAssistant()}>Ask</button>;
      }`,
    },
  });
  const action = callsite.actions.find((item) => item.owner === 'Page' && item.label === 'AskButton');
  assert.deepEqual(action.traits.authorizationGuards, [{ principals: ['staff'], invert: true }]);
});

test('shipped shell and evidence inspector resolve every state from source, with an exact pass-through, route-policy and unreachable-prop basis', () => {
  const inventory = buildPortalActionInventory();
  const coverage = buildPortalActionCoverage({ inventory });
  for (const file of ['components/layout/app-shell.tsx', 'components/evidence/evidence-inspector.tsx']) {
    assert.deepEqual(coverage.unclassifiedStates.filter((cell) => cell.action.includes(file)), [], file);
  }
  const dismiss = inventory.excludedActions.find((action) => action.id.includes('app-shell.tsx') && action.label === 'Dismiss');
  assert.match(dismiss.reason, /no mounted caller supplies it/);
  const roleSwitch = inventory.actions.find((action) => action.label === 'Role (dev)');
  assert.deepEqual(roleSwitch.traits.authorizationGuards, [{ principals: ['staff'], invert: true }]);
  const staffCells = coverage.cells.filter((cell) => cell.action === roleSwitch.id && cell.principal === 'staff' && cell.applicable === true);
  assert.ok(staffCells.length > 0 && staffCells.every((cell) => cell.state === 'denial'));
  const retest = inventory.actions.find((action) => action.label === 'Re-test' && action.file.endsWith('evidence-inspector.tsx'));
  assert.deepEqual(retest.traits.authorizationGuards, [{ roles: ['owner', 'admin', 'engineer'], principal: 'customer', invert: false }, { principals: ['staff'], invert: true }]);
  const icon = inventory.actions.find((action) => action.owner === 'ShellIconButton');
  const iconStates = actionStateApplicability(icon);
  assert.equal(iconStates.success.applicable, true);
  assert.equal(iconStates.cancel.applicable, false);
  assert.match(iconStates.cancel.reason, /mounted callers/);
});

test('a host mounted behind a principal gate in App hands that guard to controls reachable only through it', () => {
  fixture('App.tsx', "import {AppShell} from './components/layout/app-shell'; import {EvidenceInspectorHost} from './components/evidence/evidence-inspector'; export default function App({session}){return <><AppShell/>{session && session.principal !== 'staff' ? <EvidenceInspectorHost/> : null}</>}");
  const inventory = mount({
    shell: "export function AppShell(){return <button onClick={()=>{}}>Shell only</button>}",
    files: {
      'components/evidence/evidence-inspector.tsx': "export function EvidenceInspectorHost(){return <button onClick={()=>{}}>Inspect</button>}",
      'pages/page.tsx': 'export function Page(){return <a href="#settings">Settings</a>}',
    },
  });
  const inspect = byLabel(inventory, 'Inspect');
  assert.deepEqual(inspect.traits.authorizationGuards, [{ principals: ['staff'], invert: true }]);
  assert.equal(actionEligibilityDecision({ principal: 'staff', role: 'internal_admin', session: { principal: 'staff' } }, inspect.traits.authorizationGuards), false);
  assert.equal(actionEligibilityDecision({ principal: 'customer', role: 'owner', session: { role: 'owner' } }, inspect.traits.authorizationGuards), true);
  assert.deepEqual(byLabel(inventory, 'Shell only').traits.authorizationGuards, [], 'Controls the ungated shell also reaches stay unguarded');
  fs.rmSync(path.join(fixtureRoot, 'apps/web/react/src/App.tsx'));
});

test('a control gated on a published store appears only on routes whose components publish to that store', () => {
  fixture('App.tsx', "import {AppShell} from './components/layout/app-shell'; import {EvidenceInspectorHost} from './components/evidence/evidence-inspector'; export default function App(){return <><AppShell/><EvidenceInspectorHost/></>}");
  const inventory = mount({
    navigation: "export const NAV_ITEMS=[{id:'settings'},{id:'targets'}]; export const DETAIL_ROUTE_ITEMS=[];",
    router: "import {Publisher, Plain} from './page'; export function RouteView({route}){if(route==='settings') return <Publisher/>; if(route==='targets') return <Plain/>;}",
    files: {
      'components/evidence/sequence.ts': "export function usePublishSequence(items){} export function useSequence(){return null}",
      'components/evidence/evidence-inspector.tsx': `import {useSequence} from './sequence';
        export function EvidenceInspectorHost(){
          const sequence = useSequence();
          const position = sequence ? { next: true } : null;
          return <>{position ? <button onClick={()=>{}}>Next record</button> : null}<button onClick={()=>{}}>Always</button></>;
        }`,
      'pages/page.tsx': "import {usePublishSequence} from '../components/evidence/sequence'; export function Publisher(){usePublishSequence([1,2]); return <a href='#targets'>Publisher</a>} export function Plain(){return <a href='#settings'>Plain</a>}",
    },
  });
  const next = byLabel(inventory, 'Next record');
  assert.deepEqual(next.routes, ['settings']);
  assert.deepEqual(next.storeBinding, { store: 'Sequence', publishingRoutes: ['settings'] });
  assert.deepEqual(byLabel(inventory, 'Always').routes.sort(), ['settings', 'targets']);
  fs.rmSync(path.join(fixtureRoot, 'apps/web/react/src/App.tsx'));
});

const forwardedStates = (inventory, owner) => actionStateApplicability(inventory.actions.find((action) => action.owner === owner));

test('a prop invoked inside a primitive helper delegates through every caller, including forwarding wrappers and setters', () => {
  const select = "export function Select({onChange}){ function choose(next){ onChange(next); } return <button onClick={() => choose('a')}>Choose</button>; }";
  const resolved = mount({
    files: {
      'components/ui/select.tsx': select,
      'pages/page.tsx': `import {Select} from '../components/ui/select';
        function Filter({onPick}){ return <Select onChange={onPick}/>; }
        export function Page(){ const [v,setV]=useState(''); return <><Select onChange={setV}/><Filter onPick={(x)=>setV(x)}/></>; }`,
    },
  });
  const action = resolved.actions.find((item) => item.owner === 'Select');
  assert.deepEqual(action.traits.callerBindings, { onChange: { callers: 2, resolved: 2 } });
  assert.equal(forwardedStates(resolved, 'Select').reload.applicable, false);
  const opaque = mount({
    router: "import {Page} from './page'; export function RouteView({route,handlers}){if(route==='settings') return <Page onPick={handlers.pick}/>;}",
    files: {
      'components/ui/select.tsx': select,
      'pages/page.tsx': "import {Select} from '../components/ui/select'; export function Page({onPick}){ return <Select onChange={onPick}/>; }",
    },
  });
  assert.equal(forwardedStates(opaque, 'Select').reload.applicable, null);
});

test('an omitted optional callback is inert only when every read leaves no handler', () => {
  const empty = `function EmptyStateAction({onAction}){ if (onAction) return <button onClick={onAction}>Act</button>; return null; }
    export function EmptyState({title,onAction}){ return <div>{title}<EmptyStateAction onAction={onAction}/></div>; }`;
  const inert = mount({
    files: {
      'components/ui/empty-state.tsx': empty,
      'pages/page.tsx': "import {EmptyState} from '../components/ui/empty-state'; export function Page(){ const [n,setN]=useState(0); return <><EmptyState title='a'/><EmptyState title='b' onAction={() => setN(1)}/><EmptyState title='c' onAction={() => setN(2)}/></>; }",
    },
  });
  const action = inert.actions.find((item) => item.owner === 'EmptyStateAction');
  assert.deepEqual(action.traits.callerBindings, { onAction: { callers: 3, resolved: 2, omitted: 1 } });
  assert.equal(forwardedStates(inert, 'EmptyStateAction').reload.applicable, false);
  assert.match(forwardedStates(inert, 'EmptyStateAction').reload.reason, /1 omit it, which leaves no handler/);
  const invoked = mount({
    files: {
      'components/ui/empty-state.tsx': "function EmptyStateAction({onAction}){ return <button onClick={() => onAction()}>Act</button>; } export function EmptyState({onAction}){ return <EmptyStateAction onAction={onAction}/>; }",
      'pages/page.tsx': "import {EmptyState} from '../components/ui/empty-state'; export function Page(){ const [n,setN]=useState(0); return <><EmptyState/><EmptyState onAction={() => setN(1)}/><EmptyState onAction={() => setN(2)}/></>; }",
    },
  });
  assert.equal(forwardedStates(invoked, 'EmptyStateAction').reload.applicable, null, 'An unguarded call of an omitted prop is not inert');
});

test('hook-returned members and hook tuples resolve to their exact declarations; a later spread blocks', () => {
  const inventory = mount({
    files: {
      'lib/hooks.ts': `import {useCallback,useState} from 'react';
        export function useThing(id){ const [state,setState]=useState({}); const load=useCallback(() => requestJson(config,session,'/v1/things/'+id), [id]); return { ...state, reload: () => load() }; }
        export function useLate(id){ const reload=() => requestJson(config,session,'/v1/late'); return { reload, ...extra(id) }; }
        export function usePair(){ const [v,setVState]=useState(''); const setV=useCallback((next) => setVState(next), []); return [v, setV]; }`,
      'pages/page.tsx': `import {useThing,useLate,usePair} from '../lib/hooks';
        export function Page({id}){ const thing=useThing(id); const late=useLate(id); const [v,setV]=usePair();
          return <><button onClick={thing.reload}>Reload thing</button><button onClick={late.reload}>Reload late</button><button onClick={() => setV('x')}>Pick</button></>; }`,
    },
  });
  const thing = byLabel(inventory, 'Reload thing');
  assert.deepEqual(thing.traits.unresolvedCallbacks, []);
  assert.equal(thing.traits.requests[0].method, 'GET');
  assert.deepEqual(byLabel(inventory, 'Reload late').traits.unresolvedCallbacks, ['late.reload']);
  assert.deepEqual(byLabel(inventory, 'Pick').traits.unresolvedCallbacks, []);
});

test('spread props resolve through exact objects, component props and direct call sites; escaping functions block', () => {
  const button = 'export function Button({onClick,children}){return <button onClick={onClick}>{children}</button>}';
  const resolved = mount({
    files: {
      'components/ui/button.tsx': button,
      'pages/page.tsx': `import {Button} from '../components/ui/button';
        function renderAction(props){ return <Button {...props}/>; }
        function Wrapped(props){ return <Button {...props}/>; }
        export function Page(){ const [n,setN]=useState(0); const extra={ onClick: () => setN(1) };
          return <><Button {...extra}>One</Button><Wrapped onClick={() => setN(2)}/>{renderAction({ onClick: () => setN(3) })}</>; }`,
    },
  });
  assert.deepEqual(resolved.actions.find((item) => item.owner === 'Button').traits.callerBindings, { onClick: { callers: 3, resolved: 3 } });
  const escaping = mount({
    files: {
      'components/ui/button.tsx': button,
      'pages/page.tsx': `import {Button} from '../components/ui/button';
        function renderAction(props){ return <Button {...props}/>; }
        export function Page({items}){ return <>{renderAction({ onClick: () => {} })}{items.map(renderAction)}</>; }`,
    },
  });
  assert.equal(forwardedStates(escaping, 'Button').reload.applicable, null);
});

test('block-scoped redeclarations resolve to the enclosing block and stay ambiguous outside it', () => {
  const inventory = mount({
    files: {
      'components/ui/button.tsx': 'export function Button({onClick,children}){return <button onClick={onClick}>{children}</button>}',
      'pages/page.tsx': `import {Button} from '../components/ui/button';
        export function Page({mode}){ const [n,setN]=useState(0);
          if (mode) { const props={ onClick: () => setN(1) }; return <Button {...props}>First</Button>; }
          { const props={ label: 'none' }; }
          return <Button {...props}>Second</Button>; }`,
    },
  });
  const binding = inventory.actions.find((item) => item.owner === 'Button').traits.callerBindings.onClick;
  assert.deepEqual(binding, { callers: 2, resolved: 1 });
});

test('props members, destructured prop aliases and members of prop objects flow back to their declarations', () => {
  const inventory = mount({
    files: {
      'components/ui/select.tsx': "export function Select({onChange}){ return <button onClick={() => onChange('a')}>Choose</button>; }",
      'pages/page.tsx': `import {Select} from '../components/ui/select';
        function Panel({form}){ return <Select onChange={form.onCadence}/>; }
        function Refined(props){ const { model } = props; return <><Select onChange={props.onKind}/><Panel form={model}/></>; }
        export function Page(){ const [c,setC]=useState(''); const model={ onCadence: (value) => setC(value) };
          return <Refined onKind={setC} model={model}/>; }`,
    },
  });
  assert.deepEqual(inventory.actions.find((item) => item.owner === 'Select').traits.callerBindings, { onChange: { callers: 2, resolved: 2 } });
});

test('an action callback that flows from props resolves only to one exact declaration or setters, never a union', () => {
  const single = mount({
    files: {
      'pages/page.tsx': `function Refined(props){ return <button onClick={props.onReload}>Reload list</button>; }
        export function Page({config,session}){ const reload=() => requestJson(config,session,'/v1/list'); return <Refined onReload={reload}/>; }`,
    },
  });
  const reload = byLabel(single, 'Reload list');
  assert.deepEqual(reload.traits.unresolvedCallbacks, []);
  assert.equal(reload.traits.requests[0].endpointShape, '/v1/list');
  const union = mount({
    files: {
      'pages/page.tsx': `function Refined(props){ return <button onClick={props.onReload}>Reload list</button>; }
        export function Page({config,session}){ const first=() => requestJson(config,session,'/v1/a'); const second=() => requestJson(config,session,'/v1/b');
          return <><Refined onReload={first}/><Refined onReload={second}/></>; }`,
    },
  });
  assert.deepEqual(byLabel(union, 'Reload list').traits.unresolvedCallbacks, ['props.onReload']);
});

test('a ref holding only a promise executor resolver settles a confirmation; other ref values stay unresolved', () => {
  const provider = (assignment) => mount({
    files: {
      'pages/page.tsx': `import {useCallback,useRef,useState} from 'react';
        export function Page(){ const [open,setOpen]=useState(false); const resolverRef=useRef<((value: boolean) => void) | null>(null);
          const ask = () => new Promise((resolve) => { resolverRef.current = resolve; setOpen(true); });
          ${assignment}
          const settle = useCallback((value) => { const resolve = resolverRef.current; resolverRef.current = null; resolve?.(value); }, []);
          return <><button onClick={ask}>Ask</button><button onClick={() => settle(true)}>Confirm choice</button></>; }`,
    },
  });
  assert.deepEqual(byLabel(provider(''), 'Confirm choice').traits.unresolvedCallbacks, []);
  assert.deepEqual(byLabel(provider('const leak = (fn) => { resolverRef.current = fn; };'), 'Confirm choice').traits.unresolvedCallbacks, ['resolve: unresolved callable declaration']);
});

test('a local conditional callback runs each resolvable branch and forwarded request methods come from the exact options object', () => {
  const inventory = mount({
    files: {
      'pages/page.tsx': `import {useCallback} from 'react';
        function useDetail(path){ const reload = useCallback(() => requestJson(config,session,path), [path]); return { reload }; }
        export function Page({route,config,session}){ const run=useDetail('/v1/runs/1'); const finding=useDetail('/v1/findings/1');
          const activeReload = route === 'run' ? run.reload : route === 'finding' ? finding.reload : null;
          async function socFetch(path, options = {}){ return requestSocJson(config,session,path,{ method: options.method, body: options.body }); }
          const approve = async () => { await socFetch('/internal/soc/requests/1/approve', { method: 'POST', body: {} }); if (activeReload) activeReload(); };
          const read = async () => { await socFetch('/internal/soc/requests/1'); };
          return <><button onClick={approve}>Approve</button><button onClick={read}>Read</button></>; }`,
    },
  });
  const approve = byLabel(inventory, 'Approve');
  assert.deepEqual(approve.traits.unresolvedCallbacks, []);
  assert.deepEqual(approve.traits.requests.map((request) => request.method), ['POST', 'GET']);
  assert.deepEqual(byLabel(inventory, 'Read').traits.requests.map((request) => request.method), ['GET']);
});
