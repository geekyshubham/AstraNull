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
    assert.match(states[state].reason, /all 2 mounted callers.*owns the/);
  }
  const opaque = mount({
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
