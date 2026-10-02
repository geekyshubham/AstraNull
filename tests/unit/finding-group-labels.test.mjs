import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer as createViteServer } from 'vite';
import { PORTAL_ROUTE_DATASETS } from '../../apps/web/react/src/lib/types.ts';
import {
  buildTargetGroupNameMap,
  resolveTargetGroupLabel,
} from '../../apps/web/react/src/lib/finding-group-labels.mjs';

// F12: finding detail's rule-wide asset table labels target groups by recorded name.
// A cold deep link must hydrate targetGroups itself, and a failed group load must be
// reported explicitly instead of silently degrading to opaque IDs.

const CONFIG = { authMode: 'dev-headers' };
const SESSION = {
  mode: 'dev-headers',
  principal: 'customer',
  tenant_id: 'ten_finding_group_labels',
  user_id: 'usr_finding_group_labels',
  role: 'owner',
};
const NATIVE_FETCH = globalThis.fetch;
const GROUPS = [
  { id: 'tg_edge', name: 'Edge web' },
  { id: 'tg_api', display_name: 'Public API' },
  { id: 'tg_unnamed' },
];

let vite;
let fetchPortalData;
let resetPortalDataCache;

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Serves every portal dataset; target groups answer from `targetGroupsResponse()`. */
function installFetch(targetGroupsResponse) {
  const requests = [];
  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input.url;
    const route = url.split('?')[0];
    requests.push(route);
    if (route === '/v1/target-groups') return targetGroupsResponse();
    if (route === '/v1/state' || route === '/v1/tenants/current') return jsonResponse({});
    if (route === '/v1/tenant/deployment-features') return jsonResponse({ waf: false, connectors: false });
    return jsonResponse({ items: [] });
  };
  return requests;
}

function labelFor(data, groupId) {
  return resolveTargetGroupLabel(groupId, {
    names: buildTargetGroupNameMap(data.targetGroups),
    loadError: data.loadErrors?.targetGroups ?? '',
  });
}

before(async () => {
  vite = await createViteServer({
    configFile: path.resolve('vite.config.ts'),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  });
  ({ fetchPortalData, resetPortalDataCache } = await vite.ssrLoadModule('/src/lib/api.ts'));
});

afterEach(() => {
  globalThis.fetch = NATIVE_FETCH;
  resetPortalDataCache?.();
});

after(async () => {
  await vite?.close();
});

describe('finding detail route dataset policy', () => {
  it('hydrates target groups so group names do not depend on navigation history', () => {
    assert.ok(
      PORTAL_ROUTE_DATASETS['finding-detail'].includes('targetGroups'),
      'finding-detail must load targetGroups for the rule-wide asset table',
    );
  });
});

describe('target-group label resolution', () => {
  it('builds a name map from recorded names and skips unnamed groups', () => {
    const names = buildTargetGroupNameMap(GROUPS);
    assert.equal(names.get('tg_edge'), 'Edge web');
    assert.equal(names.get('tg_api'), 'Public API');
    assert.equal(names.has('tg_unnamed'), false);
    assert.equal(buildTargetGroupNameMap(undefined).size, 0);
    assert.equal(buildTargetGroupNameMap([null, 'x', {}]).size, 0);
  });

  it('labels loaded groups by name and keeps the ID visible', () => {
    const names = buildTargetGroupNameMap(GROUPS);
    assert.deepEqual(resolveTargetGroupLabel('tg_edge', { names, loadError: '' }), {
      state: 'named',
      id: 'tg_edge',
      name: 'Edge web',
    });
  });

  it('marks findings without a recorded group as ungrouped', () => {
    assert.equal(resolveTargetGroupLabel('', {}).state, 'ungrouped');
    assert.equal(resolveTargetGroupLabel(undefined).state, 'ungrouped');
  });

  it('reports a failed group load as unavailable rather than an unrecorded ID', () => {
    const failed = resolveTargetGroupLabel('tg_edge', { names: new Map(), loadError: 'Target groups failed (503)' });
    assert.deepEqual(failed, { state: 'unavailable', id: 'tg_edge', name: '' });
  });

  it('keeps unrecorded IDs distinct from load failures once groups loaded', () => {
    const names = buildTargetGroupNameMap(GROUPS);
    assert.equal(resolveTargetGroupLabel('tg_unnamed', { names, loadError: '' }).state, 'unrecorded');
    assert.equal(resolveTargetGroupLabel('tg_deleted', { names, loadError: '' }).state, 'unrecorded');
  });

  it('still shows a name already in hand even if a later refresh failed', () => {
    const names = buildTargetGroupNameMap(GROUPS);
    assert.equal(resolveTargetGroupLabel('tg_edge', { names, loadError: 'stale refresh failed' }).state, 'named');
  });
});

describe('finding detail target-group hydration', () => {
  it('resolves group names on a cold deep link with an empty cache', async () => {
    resetPortalDataCache();
    const requests = installFetch(() => jsonResponse({ items: GROUPS }));
    const data = await fetchPortalData(CONFIG, SESSION, { route: 'finding-detail' });
    assert.ok(requests.includes('/v1/target-groups'), 'cold finding-detail must request target groups');
    assert.equal(data.loadErrors.targetGroups, undefined);
    assert.equal(labelFor(data, 'tg_edge').state, 'named');
    assert.equal(labelFor(data, 'tg_edge').name, 'Edge web');
  });

  it('resolves the same names after warm navigation from Findings', async () => {
    resetPortalDataCache();
    installFetch(() => jsonResponse({ items: GROUPS }));
    await fetchPortalData(CONFIG, SESSION, { route: 'findings' });
    const warm = await fetchPortalData(CONFIG, SESSION, { route: 'finding-detail' });
    resetPortalDataCache();
    const cold = await fetchPortalData(CONFIG, SESSION, { route: 'finding-detail' });
    assert.deepEqual(labelFor(warm, 'tg_api'), labelFor(cold, 'tg_api'), 'labels must not vary by navigation history');
    assert.equal(labelFor(warm, 'tg_api').name, 'Public API');
  });

  it('surfaces a failed target-group load explicitly', async () => {
    resetPortalDataCache();
    installFetch(() => jsonResponse({ error: 'unavailable' }, 503));
    const data = await fetchPortalData(CONFIG, SESSION, { route: 'finding-detail' });
    assert.ok(data.loadErrors.targetGroups, 'the group load failure must be recorded');
    assert.equal(labelFor(data, 'tg_edge').state, 'unavailable');
    assert.equal(labelFor(data, 'tg_edge').id, 'tg_edge');
  });
});

describe('finding detail rule-asset group cell', () => {
  const source = readFileSync(new URL('../../apps/web/react/src/pages/finding-detail-view.tsx', import.meta.url), 'utf8');

  it('renders group cells through the shared resolver with the load error', () => {
    assert.match(source, /from '\.\.\/lib\/finding-group-labels\.mjs'/);
    assert.match(source, /data\.loadErrors\?\.targetGroups/);
    assert.match(source, /resolveTargetGroupLabel\(getString\(item, \['target_group_id'\], ''\), \{ names: targetGroupNames, loadError: targetGroupsLoadError \}\)/);
  });

  it('labels unavailable group names instead of showing a bare ID', () => {
    assert.match(source, /group\.state === 'unavailable'/);
    assert.match(source, /Group name unavailable/);
    assert.match(source, /Target group names are unavailable because target groups could not be loaded/);
  });
});
