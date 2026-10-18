import assert from 'node:assert/strict';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createServer as createViteServer } from 'vite';

let vite;
let requestJson;
const config = { authMode: 'dev-headers' };
const session = { mode: 'dev-headers', principal: 'customer', tenant_id: 'ten_retry', user_id: 'usr_retry', role: 'owner' };

before(async () => {
  vite = await createViteServer({
    configFile: path.resolve('vite.config.ts'),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  });
  ({ requestJson } = await vite.ssrLoadModule('/src/lib/api.ts'));
});
after(async () => { await vite?.close(); });

function limited() {
  return new Response(JSON.stringify({ error: 'rate_limited' }), {
    status: 429,
    headers: { 'content-type': 'application/json', 'retry-after': '0' },
  });
}

describe('portal mutation rate-limit retry', { concurrency: false }, () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    it(`${method} returns the first 429 without automatically repeating a mutation`, async (t) => {
      const requests = [];
      t.mock.method(globalThis, 'fetch', async (url, init) => {
        requests.push({ url, method: init.method, body: init.body });
        return requests.length === 1 ? limited() : new Response('{}');
      });
      let failure;
      try {
        await requestJson(config, session, '/v1/tenants/current/origin-clues/erase', {
          method,
          body: { confirmation_tenant_id: session.tenant_id, reason: 'Owned retry regression', dry_run: false },
        });
      } catch (error) { failure = error; }
      assert.equal(requests.length, 1);
      assert.equal(requests[0].method, method);
      assert.equal(failure?.status, 429);
      assert.equal(failure?.payload.error, 'rate_limited');
    });
  }

  for (const method of [undefined, 'GET', 'HEAD']) {
    it(`${method ?? 'default GET'} retains one bounded read-only retry`, async (t) => {
      let calls = 0;
      t.mock.method(globalThis, 'fetch', async () => {
        calls += 1;
        return calls === 1 ? limited() : new Response(JSON.stringify({ readable: true }));
      });
      assert.deepEqual(await requestJson(config, session, '/v1/tenants/current', { method }), { readable: true });
      assert.equal(calls, 2);
    });
  }

  it('a repeated read-only 429 is surfaced rather than retried indefinitely', async (t) => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => { calls += 1; return limited(); });
    await assert.rejects(requestJson(config, session, '/v1/tenants/current'), (error) => error.status === 429);
    assert.equal(calls, 2);
  });
});
