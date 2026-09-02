import assert from 'node:assert/strict';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer as createViteServer } from 'vite';
import {
  createPayloadCommitGate,
  runGenerationKeyedPayload,
} from '../../apps/web/react/src/lib/payload-commit-generation.mjs';

let vite;
let fetchPortalData;
let fetchPortalDatasets;
let resetPortalDataCache;

const CONFIG = { authMode: 'dev-headers' };
const SESSION = {
  mode: 'dev-headers',
  principal: 'customer',
  tenant_id: 'ten_generation_cache',
  user_id: 'usr_generation_cache',
  role: 'owner',
};
const NATIVE_FETCH = globalThis.fetch;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function secretNames(data) {
  return data.secrets.map((secret) => secret.name);
}

before(async () => {
  vite = await createViteServer({
    configFile: path.resolve('vite.config.ts'),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  });
  ({
    fetchPortalData,
    fetchPortalDatasets,
    resetPortalDataCache,
  } = await vite.ssrLoadModule('/src/lib/api.ts'));
});

afterEach(() => {
  globalThis.fetch = NATIVE_FETCH;
  resetPortalDataCache();
});

after(async () => {
  await vite?.close();
});

describe('portal payload commit generation', () => {
  it('keeps newer settings data when older integrations resolves and rejects late', async () => {
    const gate = createPayloadCommitGate('integrations');
    const olderIntegrations = deferred();
    const newerSettings = deferred();
    const committed = [];
    const errors = [];
    const settled = [];
    let oldIsCurrent;

    const oldRequest = runGenerationKeyedPayload({
      gate,
      routeKey: 'integrations',
      load: (isCurrent) => {
        oldIsCurrent = isCurrent;
        return olderIntegrations.promise;
      },
      onCommit: (payload) => committed.push(payload),
      onError: (error) => errors.push(error.message),
      onSettled: () => settled.push('integrations'),
    });

    assert.equal(oldIsCurrent(), true);
    gate.activate('settings');
    assert.equal(oldIsCurrent(), false, 'the load callback keeps authority from its original ticket');
    const newRequest = runGenerationKeyedPayload({
      gate,
      routeKey: 'settings',
      load: () => newerSettings.promise,
      onCommit: (payload) => committed.push(payload),
      onError: (error) => errors.push(error.message),
      onSettled: () => settled.push('settings'),
    });

    newerSettings.resolve({ route: 'settings', tenant: 'newer-settings-data' });
    assert.equal(await newRequest, true);
    olderIntegrations.resolve({ route: 'integrations', tenant: 'stale-integrations-data' });
    assert.equal(await oldRequest, false);
    assert.deepEqual(committed, [{ route: 'settings', tenant: 'newer-settings-data' }]);
    assert.deepEqual(errors, []);
    assert.deepEqual(settled, ['settings']);

    const staleFailure = deferred();
    const staleRequest = runGenerationKeyedPayload({
      gate,
      routeKey: 'settings',
      load: () => staleFailure.promise,
      onCommit: (payload) => committed.push(payload),
      onError: (error) => errors.push(error.message),
      onSettled: () => settled.push('stale-settings'),
    });
    gate.activate('integrations');
    staleFailure.reject(new Error('late stale failure'));
    assert.equal(await staleRequest, false);
    assert.deepEqual(errors, [], 'a stale rejection cannot overwrite the newer route state');
    assert.deepEqual(settled, ['settings'], 'a stale finally callback is ignored');
  });

  it('rejects a late Integrations secrets payload from both React state and shared cache', async () => {
    resetPortalDataCache();
    const staleIntegrations = deferred();
    const currentSettings = deferred();
    const freshSecret = { id: 'sec_fresh', name: 'fresh-settings-secret' };
    const staleSecret = { id: 'sec_stale', name: 'stale-integrations-secret' };
    let secretsRequests = 0;

    globalThis.fetch = async (input) => {
      const path = typeof input === 'string' ? input : input.url;
      if (path === '/v1/secrets') {
        secretsRequests += 1;
        const payload = await (secretsRequests === 1
          ? staleIntegrations.promise
          : currentSettings.promise);
        return jsonResponse(payload);
      }
      if (path === '/v1/state') return jsonResponse({ readiness: { score: 91 } });
      throw new Error(`unexpected portal request: ${path}`);
    };

    const gate = createPayloadCommitGate('integrations');
    let renderedData = null;
    let staleIsCurrent;
    const oldRequest = runGenerationKeyedPayload({
      gate,
      routeKey: 'integrations',
      load: (isCurrent) => {
        staleIsCurrent = isCurrent;
        return fetchPortalDatasets(CONFIG, SESSION, ['secrets'], isCurrent);
      },
      onCommit: (payload) => { renderedData = payload; },
      onError: (error) => assert.fail(error),
    });
    assert.equal(secretsRequests, 1);

    gate.activate('settings');
    const newRequest = runGenerationKeyedPayload({
      gate,
      routeKey: 'settings',
      load: (isCurrent) => fetchPortalDatasets(CONFIG, SESSION, ['secrets'], isCurrent),
      onCommit: (payload) => { renderedData = payload; },
      onError: (error) => assert.fail(error),
    });
    assert.equal(secretsRequests, 2);

    currentSettings.resolve({ items: [freshSecret] });
    assert.equal(await newRequest, true);
    assert.deepEqual(secretNames(renderedData), [freshSecret.name]);

    staleIntegrations.resolve({ items: [staleSecret] });
    assert.equal(await oldRequest, false);
    assert.equal(staleIsCurrent(), false);
    assert.deepEqual(secretNames(renderedData), [freshSecret.name], 'stale data cannot reach React state');

    const dashboardData = await fetchPortalData(CONFIG, SESSION, {
      datasets: ['state'],
      includeCore: false,
      force: true,
    });
    assert.deepEqual(secretNames(dashboardData), [freshSecret.name]);

    const revisitedSettings = await fetchPortalData(CONFIG, SESSION, {
      datasets: ['secrets'],
      includeCore: false,
    });
    assert.equal(secretsRequests, 2, 'Settings must reuse the current cache without a masking refetch');
    assert.deepEqual(secretNames(revisitedSettings), [freshSecret.name]);
  });

  it('caches current non-App dataset callers by default', async () => {
    resetPortalDataCache();
    let secretsRequests = 0;
    globalThis.fetch = async (input) => {
      const path = typeof input === 'string' ? input : input.url;
      assert.equal(path, '/v1/secrets');
      secretsRequests += 1;
      return jsonResponse({ items: [{ id: 'sec_default', name: 'default-cached-secret' }] });
    };

    await fetchPortalDatasets(CONFIG, SESSION, ['secrets']);
    const cached = await fetchPortalData(CONFIG, SESSION, {
      datasets: ['secrets'],
      includeCore: false,
    });

    assert.equal(secretsRequests, 1);
    assert.deepEqual(secretNames(cached), ['default-cached-secret']);
  });
});


describe('portal dataset error truthfulness', () => {
  it('reports missing collection and singleton routes as load failures', async () => {
    globalThis.fetch = async (input) => {
      const requestPath = typeof input === 'string' ? input : input.url;
      assert.ok(['/v1/targets', '/v1/state'].includes(requestPath));
      return new Response(JSON.stringify({
        error: 'not_found',
        message: 'internal route diagnostic must not become empty state',
      }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      });
    };

    const data = await fetchPortalDatasets(CONFIG, SESSION, ['targets', 'state']);

    assert.deepEqual(data.targets, []);
    assert.equal(data.state, null);
    assert.equal(data.loadErrors.targets, 'That record was not found, or you do not have access to it.');
    assert.equal(data.loadErrors.state, 'That record was not found, or you do not have access to it.');
    assert.equal(data.error, 'That record was not found, or you do not have access to it.');
  });
});
