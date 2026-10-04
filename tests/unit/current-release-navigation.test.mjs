/**
 * Current release: scoped list return state, customer sidebar order, single presentation and
 * legacy route resolution. Uses an in-memory sessionStorage; nothing is persisted to disk.
 */
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import {
  NAV_STATE_PREFIX,
  NAV_STATE_TTL_MS,
  clearNavState,
  loadNavState,
  navScopeKey,
  sanitizeNavState,
  saveNavState,
} from '../../apps/web/react/src/lib/nav-state.mjs';
import { DETAIL_ROUTE_ITEMS, NAV_ITEMS, ROUTE_BY_ID, resolvePortalRoute } from '../../apps/web/react/src/lib/navigation.ts';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');

function memoryStorage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    key: (index) => [...map.keys()][index] ?? null,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => { map.set(key, String(value)); },
    removeItem: (key) => { map.delete(key); },
    _map: map,
  };
}

describe('scoped list return state (EI-05, TF return)', () => {
  let originalWindow;
  beforeEach(() => {
    originalWindow = globalThis.window;
    globalThis.window = { sessionStorage: memoryStorage() };
  });
  afterEach(() => {
    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  });

  it('scopes by tenant, user and role and refuses to persist without a tenant', () => {
    assert.equal(navScopeKey({ tenant_id: 'ten_a', user_id: 'usr_1', role: 'owner' }), 'ten_a|usr_1|owner');
    assert.equal(navScopeKey({ user_id: 'usr_1', role: 'owner' }), '');
    assert.equal(saveNavState('', 'findings', { page: 2 }), false);
  });

  it('keeps only allowlisted, non-sensitive fields', () => {
    const clean = sanitizeNavState({
      filters: { status: 'open', q: 'checkout login', access_token: 'eyJhbGciOi', password: 'hunter2', invite_token: 'abc', group: 'tg_1' },
      sort: 'severity',
      page: 3,
      scrollTop: 1200,
      selectedRowId: 'fnd_1',
      focusKey: 'finding-fnd_1',
      draft: { notes: 'secret' },
      payload: 'raw',
    });
    assert.deepEqual(clean, {
      filters: { status: 'open', q: 'checkout login', group: 'tg_1' },
      sort: 'severity',
      selectedRowId: 'fnd_1',
      focusKey: 'finding-fnd_1',
      page: 3,
      scrollTop: 1200,
    });
  });

  it('restores within the TTL and expires afterwards', () => {
    const scope = 'ten_a|usr_1|owner';
    const now = 1_000_000;
    saveNavState(scope, 'findings', { filters: { status: 'closed' }, page: 1 }, now);
    assert.deepEqual(loadNavState(scope, 'findings', now + 1000), { filters: { status: 'closed' }, page: 1 });
    assert.equal(loadNavState(scope, 'findings', now + NAV_STATE_TTL_MS + 1), null);
    assert.equal(window.sessionStorage.length, 0, 'expired state is removed');
  });

  it('never leaks one tenant or role state into another', () => {
    saveNavState('ten_a|usr_1|owner', 'targets', { filters: { q: 'pay' } });
    saveNavState('ten_b|usr_1|viewer', 'targets', { filters: { q: 'api' } });
    assert.equal(loadNavState('ten_b|usr_1|owner', 'targets'), null);
    clearNavState('ten_b|usr_1|viewer');
    const keys = [...window.sessionStorage._map.keys()];
    assert.deepEqual(keys, [`${NAV_STATE_PREFIX}ten_b|usr_1|viewer:targets`]);
    clearNavState();
    assert.equal(window.sessionStorage.length, 0);
  });
});

describe('customer navigation (shared-shell P2, contract)', () => {
  it('puts Targets before Target groups', () => {
    const ids = NAV_ITEMS.map((item) => item.id);
    assert.ok(ids.indexOf('targets') < ids.indexOf('target-groups'));
  });

  it('removes deferred execution history from the sidebar but keeps its address resolving', () => {
    assert.equal(NAV_ITEMS.some((item) => item.id === 'runs'), false);
    assert.ok(DETAIL_ROUTE_ITEMS.some((item) => item.id === 'runs'));
    assert.equal(resolvePortalRoute('/app', '#runs'), 'runs');
    assert.equal(resolvePortalRoute('/app', '#findings?variant=classic'), 'findings');
  });

  it('groups account tasks and uses plain labels', () => {
    for (const id of ['settings', 'support', 'subscription']) assert.equal(ROUTE_BY_ID.get(id)?.group, 'account');
    assert.equal(ROUTE_BY_ID.get('subscription')?.label, 'Plan & usage');
    assert.equal(ROUTE_BY_ID.get('checks')?.label, 'Check library');
  });
});

describe('one customer presentation', () => {
  it('routes findings to the refined page without a variant switch', () => {
    const router = read('apps/web/react/src/pages/router.tsx');
    assert.match(router, /route === 'findings'[\s\S]*<FindingsPage/);
    for (const path of [
      'apps/web/react/src/pages/refined/findings-refined.tsx',
      'apps/web/react/src/pages/refined/finding-group-detail.tsx',
      'apps/web/react/src/pages/target-detail-view.tsx',
    ]) {
      assert.doesNotMatch(read(path), /VariantSwitch|DesignVariantSwitch|useDesignVariant/, path);
    }
  });

  it('mounts the inspector host only inside the authenticated shell', () => {
    const app = read('apps/web/react/src/App.tsx');
    assert.match(app, /\{session \? \(\s*<EvidenceInspectorHost/);
    assert.ok(app.indexOf('<EvidenceInspectorHost') > app.indexOf('<AppShell'), 'host renders after the shell, never on public pages');
  });

  it('finding and group pages open evidence in place instead of run or evidence detail hops', () => {
    const group = read('apps/web/react/src/pages/refined/finding-group-detail.tsx');
    assert.doesNotMatch(group, /Open lead finding for full evidence/);
    assert.match(group, /entry: 'group_member'/);
    const detail = read('apps/web/react/src/pages/finding-detail-view.tsx');
    assert.doesNotMatch(detail, /buildDetailHref\('run-detail'/);
    assert.doesNotMatch(detail, /evidenceIds\[0\]/);
    assert.match(detail, /Review this retest/);
  });
});

describe('review fixes: persisted filter allowlist (NAV-01)', () => {
  let originalWindow;
  beforeEach(() => {
    originalWindow = globalThis.window;
    globalThis.window = { sessionStorage: memoryStorage() };
  });
  afterEach(() => {
    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  });

  it('persists only supported filter keys with bounded, non-credential values', async () => {
    const { NAV_FILTER_KEYS } = await import('../../apps/web/react/src/lib/nav-state.mjs');
    assert.ok(['q', 'tag', 'verification', 'group', 'family', 'service_role', 'criticality', 'status'].every((key) => key in NAV_FILTER_KEYS));
    const clean = sanitizeNavState({
      filters: {
        unrelated_metadata: 'x',
        raw_payload: '{"a":1}',
        q: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl',
        tag: 'env:prod',
        verification: 'unverified',
        family: 'waf',
        service_role: 'login',
        criticality: 'high',
        group: 'tg_checkout',
        owner: 'Bearer abc.def',
        status: 'not a slug!',
      },
      sort: 'severity',
      page: 2,
    });
    assert.deepEqual(clean.filters, { tag: 'env:prod', verification: 'unverified', group: 'tg_checkout', family: 'waf', service_role: 'login', criticality: 'high' });
    assert.equal(clean.sort, 'severity');
    assert.equal(clean.page, 2);
  });

  it('refuses credential-shaped selection or focus ids', () => {
    const clean = sanitizeNavState({ selectedRowId: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln', focusKey: 'finding-fnd_1' });
    assert.deepEqual(clean, { focusKey: 'finding-fnd_1' });
  });
});
