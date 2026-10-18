import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { parseAst } from 'rolldown/parseAst';
import {
  assertPublicPortalAction, buildPublicPortalActionCoverage, buildPublicPortalActionInventory,
  PUBLIC_ACTION_STATES, PUBLIC_OBSERVATIONS, publicActionApplicability, reconcilePublicPortalActionCoverage,
} from '../helpers/portal-public-action-coverage.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-public-actions-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));
function fixture(source) {
  const directory = path.join(root, 'apps/web/react/src');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'App.tsx'), "import {PublicLandingPage} from './page'; export function App(){ const path=window.location.pathname;if(path==='/'||path==='/landing.html') return <PublicLandingPage/>;return null;}");
  fs.writeFileSync(path.join(directory, 'page.tsx'), source);
  return buildPublicPortalActionInventory({ root });
}
const shipped = buildPublicPortalActionCoverage();
const named = (label) => shipped.inventory.actions.find((action) => action.label === label);

test('all pre-existing applicable public obligations remain and the three demo controls resolve without dropping aliases', () => {
  assert.equal(shipped.inventory.actions.length, 131);
  const resolved = new Set(['Open demo workspace (sample data)', 'Skip: open as demo admin', 'Fill demo credentials'].map((label) => named(label).id));
  assert.equal(shipped.cells.filter((cell) => cell.applicable === true && !resolved.has(cell.action)).length, 1157);
  assert.equal(shipped.cells.filter((cell) => cell.applicable === true && resolved.has(cell.action)).length, 16);
  assert.deepEqual(shipped.unclassifiedStates, []);
  assert.deepEqual(shipped.inventory.unresolved, []);
  for (const label of ['Open demo workspace (sample data)', 'Skip: open as demo admin', 'Fill demo credentials']) {
    assert.equal(named(label).routes.length, 2);
  }
});

test('landing demo retains visitor identity and both credential HTTP and local dev-header configuration alternatives', () => {
  const action = named('Open demo workspace (sample data)');
  assert.deepEqual(action.lanes, ['visitor']);
  const states = publicActionApplicability(action);
  for (const state of ['success', 'busy', 'error-retry', 'denial', 'reload']) assert.equal(states[state].applicable, true, state);
  assert.deepEqual(action.demoTransition.alternatives.map((alternative) => alternative.kind), ['password-http', 'dev-header-session']);
  assert.deepEqual(action.demoTransition.alternatives[0].request, { method: 'POST', path: '/v1/auth/login' });
  assert.match(states.busy.reason, /password|HTTP/);
  assert.deepEqual(action.demoTransition.pending, { callback: 'openDemo', guard: 'demoPending.current', disabled: 'demoLoading', loading: 'demoLoading' });
});

test('dev-header skip is a guarded local session transition, not a credential-free HTTP login', () => {
  const action = named('Skip: open as demo admin');
  const states = publicActionApplicability(action, 'dev-headers');
  assert.equal(states.success.applicable, true);
  assert.equal(states.reload.applicable, true);
  assert.equal(states['error-retry'].applicable, false);
  for (const lane of ['password', 'staging', 'unknown', 'oidc-disabled', 'idp-redirect']) {
    assert.ok(Object.values(publicActionApplicability(action, lane)).every((state) => state.applicable === false), lane);
  }
});

test('fill-demo resolves its actual lexical state setters and challenge-reset callbacks only', () => {
  const action = named('Fill demo credentials');
  const states = publicActionApplicability(action, 'password');
  assert.equal(states.success.applicable, true);
  assert.ok(Object.entries(states).every(([state, decision]) => decision.applicable === (state === 'success')));
  const changed = structuredClone(action);
  changed.handlers.onClick = changed.handlers.onClick.replace('clearMfaChallenge()', 'unboundCallback()');
  assert.ok(Object.values(publicActionApplicability(changed, 'password')).every((state) => state.applicable === null));
});

test('a known demo callback name with a changed defining body stays blocking', () => {
  const actual = fixture("function enterDemoPortal(){return fetch('/v1/other',{method:'POST'})} export function PublicLandingPage(){return <button onClick={()=>enterDemoPortal(config.portalPath,config)}>Demo</button>}");
  assert.ok(Object.values(publicActionApplicability(actual.actions[0])).every((state) => state.applicable === null));
});

test('actual demo callback effect changes and altered config guards revert to unresolved without a name/hash whitelist', () => {
  const source = fs.readFileSync(new URL('../../apps/web/react/src/pages/public-pages.tsx', import.meta.url), 'utf8');
  const definition = parseAst(source, { lang: 'tsx' }).body.find((node) => node.type === 'FunctionDeclaration' && node.id?.name === 'enterDemoPortal');
  assert.ok(definition);
  const callback = source.slice(definition.start, definition.end);
  const component = 'export function PublicLandingPage(){return <button onClick={()=>enterDemoPortal(config.portalPath,config)}>Demo</button>}';
  const positive = fixture(callback + component).actions[0];
  assert.equal(publicActionApplicability(positive).success.applicable, true);
  for (const change of [
    callback.replace("config.authMode !== 'dev-headers'", "config.authMode === 'dev-headers'"),
    callback.replace("const res = await fetch", "await fetch('/v1/unreviewed', {method:'POST'}); const res = await fetch"),
    callback.replace('navigateSpa(portalPath);', 'onInjected();'),
    callback.replace('saveSession({', 'unknownSessionWriter({'),
    callback.replace("navigateSpa(config.loginUrl || '/login')", "navigateSpa('/unreviewed')"),
  ]) {
    assert.notEqual(change, callback);
    const action = fixture(change + component).actions[0];
    assert.ok(Object.values(publicActionApplicability(action)).every((state) => state.applicable === null));
  }
});

test('pending wrapper requires actual false-initialized React ref, synchronous single-flight guard, bound loading state and finally cleanup', () => {
  const source = fs.readFileSync(new URL('../../apps/web/react/src/pages/public-pages.tsx', import.meta.url), 'utf8');
  const definition = parseAst(source, { lang: 'tsx' }).body.find((node) => node.type === 'FunctionDeclaration' && node.id?.name === 'enterDemoPortal');
  const callback = source.slice(definition.start, definition.end);
  const component = `import {useRef,useState} from 'react'; export function PublicLandingPage(){
    const [demoLoading,setDemoLoading]=useState(false);const demoPending=useRef(false);
    async function openDemo(){if(demoPending.current)return;demoPending.current=true;setDemoLoading(true);try{await enterDemoPortal(config.portalPath,config);}finally{demoPending.current=false;setDemoLoading(false);}}
    return <button loading={demoLoading} disabled={demoLoading} onClick={()=>void openDemo()}>Demo</button>;
  }`;
  assert.equal(fixture(callback + component).actions[0].demoTransition.pending.guard, 'demoPending.current');
  for (const change of [
    component.replace('if(demoPending.current)return;', ''),
    component.replace('demoPending.current=true;', 'demoPending.current=false;'),
    component.replace('useRef(false)', 'unboundRef(false)'),
    component.replace('disabled={demoLoading}', 'disabled={false}'),
    component.replace('setDemoLoading(false)', 'onInjected()'),
    component.replace('try{await', 'try{onInjected();await'),
  ]) {
    const action = fixture(callback + change).actions[0];
    assert.equal(action.demoTransition, null);
    assert.ok(Object.values(publicActionApplicability(action)).every((state) => state.applicable === null));
  }
});

test('activation parameters and owner-local declarations cannot impersonate the module demo callback', () => {
  const source = fs.readFileSync(new URL('../../apps/web/react/src/pages/public-pages.tsx', import.meta.url), 'utf8');
  const definition = parseAst(source, { lang: 'tsx' }).body.find((node) => node.type === 'FunctionDeclaration' && node.id?.name === 'enterDemoPortal');
  const callback = source.slice(definition.start, definition.end);
  for (const component of [
    'export function PublicLandingPage(){return <button onClick={(enterDemoPortal)=>enterDemoPortal(config.portalPath,config)}>Demo</button>}',
    'export function PublicLandingPage(){function enterDemoPortal(a,b){onInjected()}return <button onClick={()=>enterDemoPortal(config.portalPath,config)}>Demo</button>}',
    'export function PublicLandingPage(){const enterDemoPortal=(a,b)=>onInjected();return <button onClick={()=>enterDemoPortal(config.portalPath,config)}>Demo</button>}',
    'export function PublicLandingPage({enterDemoPortal}){return <button onClick={()=>enterDemoPortal(config.portalPath,config)}>Demo</button>}',
  ]) {
    const action = fixture(callback + component).actions[0];
    assert.equal(action.demoTransition, null);
    assert.equal(Object.values(publicActionApplicability(action)).filter((state) => state.applicable === null).length, 8);
  }
});

test('React setter provenance requires an unshadowed hook call in the actual owner scope, not a prop or unused nested function', () => {
  for (const component of [
    `import {useState} from 'react'; export function PublicLandingPage({useState}){const [value,setValue]=useState('');return <button onClick={()=>setValue('draft')}>Local</button>}`,
    `import {useState} from 'react'; export function PublicLandingPage(){function useState(){return onInjected()}const [value,setValue]=useState('');return <button onClick={()=>setValue('draft')}>Local</button>}`,
    `import {useState} from 'react'; export function PublicLandingPage({onInjected}){function unused(){const [value,onInjected]=useState('');return value}return <button onClick={()=>onInjected('draft')}>Local</button>}`,
  ]) {
    const action = fixture(component).actions[0];
    assert.equal(Object.values(publicActionApplicability(action)).filter((state) => state.applicable === null).length, 8);
  }
});

test('pending-ref provenance cannot come from a shadowed React hook or an unused nested function', () => {
  const source = fs.readFileSync(new URL('../../apps/web/react/src/pages/public-pages.tsx', import.meta.url), 'utf8');
  const definition = parseAst(source, { lang: 'tsx' }).body.find((node) => node.type === 'FunctionDeclaration' && node.id?.name === 'enterDemoPortal');
  const callback = source.slice(definition.start, definition.end);
  const component = `import {useRef,useState} from 'react'; export function PublicLandingPage(){
    const [demoLoading,setDemoLoading]=useState(false);const demoPending=useRef(false);
    async function openDemo(){if(demoPending.current)return;demoPending.current=true;setDemoLoading(true);try{await enterDemoPortal(config.portalPath,config);}finally{demoPending.current=false;setDemoLoading(false);}}
    return <button loading={demoLoading} disabled={demoLoading} onClick={()=>void openDemo()}>Demo</button>;
  }`;
  for (const changed of [
    component.replace('PublicLandingPage()', 'PublicLandingPage({useRef})'),
    component.replace('PublicLandingPage()', 'PublicLandingPage({useState})'),
    component.replace('const demoPending=useRef(false);', 'function unused(){const demoPending=useRef(false);}'),
    component.replace('const [demoLoading,setDemoLoading]=useState(false);', 'function unused(){const [demoLoading,setDemoLoading]=useState(false);}'),
  ]) {
    const action = fixture(callback + changed).actions[0];
    assert.equal(action.demoTransition, null);
    assert.equal(Object.values(publicActionApplicability(action)).filter((state) => state.applicable === null).length, 8);
  }
});

test('local callback proof rejects additional network, session, navigation and injected effects', () => {
  for (const extra of ["fetch('/v1/write',{method:'POST'})", 'saveSession({})', "navigateSpa('/app')", 'onInjected()', "setShowPassword(true); fetch('/v1/write',{method:'POST'})"]) {
    const action = structuredClone(named('Fill demo credentials'));
    action.handlers.onClick = action.handlers.onClick.replace(/}\s*$/, `${extra}; }`);
    assert.ok(Object.values(publicActionApplicability(action, 'password')).every((state) => state.applicable === null), extra);
  }
});

test('event/updater parameters cannot impersonate a React setter or lexical reset callback', () => {
  for (const handler of [
    '(setPassword) => setPassword("draft")',
    '() => setPassword((setPassword) => { setPassword("draft"); return "draft"; })',
    '(clearMfaChallenge) => { setPassword("draft"); clearMfaChallenge(); }',
    '() => setPassword(onInjected)',
    '() => setPassword(props.updater)',
  ]) {
    const action = structuredClone(named('Fill demo credentials'));
    action.handlers.onClick = handler;
    assert.ok(Object.values(publicActionApplicability(action, 'password')).every((state) => state.applicable === null));
  }
});

test('local-state proof rejects delete and opaque spread effects but preserves proven owned plain-state updater spreads', () => {
  for (const extra of ['delete external.profile;', 'setPassword({...injected});', 'setPassword(current=>({...injected}));']) {
    const action = structuredClone(named('Fill demo credentials'));
    action.handlers.onClick = `() => { ${extra} setPassword('draft'); }`;
    assert.ok(Object.values(publicActionApplicability(action, 'password')).every((state) => state.applicable === null), extra);
  }
  const safe = fixture(`import {useState} from 'react';export function PublicLandingPage(){const [value,setValue]=useState({});return <button onClick={()=>setValue(current=>({...current,cleared:true}))}>Clear</button>}`).actions[0];
  assert.equal(publicActionApplicability(safe).success.applicable, true);
  const unsafe = fixture(`import {useState} from 'react';export function PublicLandingPage({injected}){const [value,setValue]=useState({});function inject(){setValue(injected)}return <button onClick={()=>setValue(current=>({...current,cleared:true}))}>Clear</button>}`).actions[0];
  assert.ok(Object.values(publicActionApplicability(unsafe)).every((state) => state.applicable === null));
});

test('an enclosing block binding shadows the actual owner setter/callback for that action only', () => {
  const actual = fixture(`import {useState} from 'react';export function PublicLandingPage({onInjected}){const [value,setValue]=useState('');
    const safe=<button onClick={()=>setValue('draft')}>Safe</button>;
    {const setValue=onInjected;return <><button onClick={()=>setValue('draft')}>Shadow</button>{safe}</>}}`);
  assert.equal(publicActionApplicability(actual.actions.find((action) => action.label === 'Safe')).success.applicable, true);
  assert.ok(Object.values(publicActionApplicability(actual.actions.find((action) => action.label === 'Shadow'))).every((state) => state.applicable === null));
});

test('changed lexical challenge callback is not excused by a state setter elsewhere in the handler', () => {
  const action = structuredClone(named('Fill demo credentials'));
  action.localCallbacks.find((callback) => callback.name === 'clearMfaChallenge').source += " fetch('/v1/write');";
  assert.ok(Object.values(publicActionApplicability(action, 'password')).every((state) => state.applicable === null));
});

test('unresolved visitor callbacks remain eight blocking states instead of local or N/A', () => {
  const actual = fixture('export function PublicLandingPage({onDemo}){return <button onClick={onDemo}>Demo</button>}');
  assert.equal(Object.keys(publicActionApplicability(actual.actions[0])).length, PUBLIC_ACTION_STATES.length);
  assert.ok(Object.values(publicActionApplicability(actual.actions[0])).every((state) => state.applicable === null));
});

// These are validator-unit simulations, never browser execution receipts or accepted capture inputs.
function context() {
  const attachments = [];
  return { testId: 'unit-validator-simulation', titlePath: ['validator simulation'], retry: 0,
    attach: async (name, attachment) => attachments.push({ name, ...attachment }), attachments };
}
function fixtureCoverage() {
  return buildPublicPortalActionCoverage({ inventory: fixture("export function PublicLandingPage(){return <a href='/login'>Sign in</a>}") });
}
test('receipt attaches only after completed matching assertions; a failed callback attaches nothing', async () => {
  const coverage = fixtureCoverage();
  const info = context();
  await assert.rejects(assertPublicPortalAction(info, coverage, { label: 'Sign in' }, '/', 'success', async () => { throw new Error('actual assertion failed'); }), /actual assertion failed/);
  assert.equal(info.attachments.length, 0);
  const receipt = await assertPublicPortalAction(info, coverage, { label: 'Sign in' }, '/', 'success', async () => [PUBLIC_OBSERVATIONS.navigation]);
  assert.equal(info.attachments.length, 1);
  const result = reconcilePublicPortalActionCoverage(coverage, [{ testId: info.testId, titlePath: info.titlePath, retry: 0, status: 'passed', receipts: [receipt] }]);
  assert.equal(result.covered.length, 1);
  assert.equal(result.complete, false);
  assert.equal(result.uncovered.length, 5);
});

test('stale source, ambiguous actions, retries, nonapplicable states and unreviewed observations cannot attach proof', async () => {
  const coverage = fixtureCoverage();
  const info = context();
  await assert.rejects(assertPublicPortalAction({ ...info, retry: 1 }, coverage, {}, '/', 'success', async () => [PUBLIC_OBSERVATIONS.navigation]), /no-retry/);
  await assert.rejects(assertPublicPortalAction(info, coverage, { label: 'Absent' }, '/', 'success', async () => [PUBLIC_OBSERVATIONS.navigation]), /got 0/);
  await assert.rejects(assertPublicPortalAction(info, coverage, {}, '/', 'busy', async () => [PUBLIC_OBSERVATIONS.navigation]), /applicable/);
  await assert.rejects(assertPublicPortalAction(info, coverage, {}, '/', 'success', async () => ['fabricated observation']), /Reviewed/);
  fs.appendFileSync(path.join(root, 'apps/web/react/src/page.tsx'), '\n// source changed');
  await assert.rejects(assertPublicPortalAction(info, coverage, {}, '/', 'success', async () => [PUBLIC_OBSERVATIONS.navigation]), /stale/);
  assert.equal(info.attachments.length, 0);
});

test('terminal failed, skipped, retried, mismatched or stale proofs and duplicate receipts remain rejected', async () => {
  const coverage = fixtureCoverage();
  const info = context();
  const receipt = await assertPublicPortalAction(info, coverage, {}, '/', 'success', async () => [PUBLIC_OBSERVATIONS.navigation]);
  const passed = { testId: info.testId, titlePath: info.titlePath, retry: 0, status: 'passed', receipts: [receipt] };
  for (const change of [{ status: 'failed' }, { status: 'skipped' }, { retry: 1 }, { testId: 'other' }, { receipts: [{ ...receipt, sourceDigest: '0'.repeat(64) }] }, { titlePath: ['other'] }]) {
    const result = reconcilePublicPortalActionCoverage(coverage, [{ ...passed, ...change }]);
    assert.equal(result.covered.length, 0);
    assert.equal(result.rejected.length, 1);
  }
  const duplicate = reconcilePublicPortalActionCoverage(coverage, [{ ...passed, receipts: [receipt, receipt] }]);
  assert.equal(duplicate.covered.length, 1);
  assert.equal(duplicate.rejected[0].reason, 'duplicate-public-action-proof');
});
