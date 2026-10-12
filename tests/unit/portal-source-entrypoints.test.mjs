import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createPortalSourceServer } from '../helpers/portal-playwright-server.mjs';

// Source documents and internal API requests share a prefix, not an upstream.
test('source staff entry documents stay on Vite while internal APIs retain their proxy', { timeout: 30_000 }, async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'astranull-source-entrypoints-'));
  const upstreamRequests = [];
  const api = http.createServer((req, res) => {
    upstreamRequests.push({ method: req.method, url: req.url });
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ upstream: true, method: req.method, url: req.url }));
  });
  await new Promise((resolve) => api.listen(0, '127.0.0.1', resolve));
  const upstream = `http://127.0.0.1:${api.address().port}`;
  let source;
  try {
    source = await createPortalSourceServer({ cacheDir, server: {
      host: '127.0.0.1', port: 0, strictPort: false, hmr: false,
      proxy: { '/v1': upstream, '/ready': upstream, '/internal': upstream },
    } });
    await source.listen();
    const base = `http://127.0.0.1:${source.httpServer.address().port}`;
    for (const entry of ['/app', '/internal/admin', '/internal/soc', '/internal/admin/login']) {
      const response = await fetch(`${base}${entry}?entry=direct`);
      assert.equal(response.status, 200, entry);
      assert.match(response.headers.get('content-type'), /text\/html/, entry);
      const document = await response.text();
      assert.match(document, /src="\/src\/main\.tsx"/, entry);
      assert.match(document, /\/\@vite\/client/, entry);
      assert.doesNotMatch(document, /src="\/react-app\.js"/, entry);
    }
    const head = await fetch(`${base}/internal/admin`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.match(head.headers.get('content-type'), /text\/html/);
    assert.equal(await head.text(), '');
    assert.deepEqual(upstreamRequests, []);
    const cases = [
      ['GET', '/internal/admin/tenants?limit=1'],
      ['GET', '/internal/administer'],
      ['POST', '/internal/admin'],
      ['POST', '/internal/soc/kill-switch'],
      ['GET', '/internal/admin/overview'],
      ['GET', '/v1/config'],
    ];
    for (const [method, url] of cases) {
      const response = await fetch(`${base}${url}`, { method });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { upstream: true, method, url });
    }
    assert.deepEqual(upstreamRequests, cases.map(([method, url]) => ({ method, url })));
  } finally {
    await source?.close();
    api.closeAllConnections();
    await new Promise((resolve) => api.close(resolve));
    await rm(cacheDir, { recursive: true, force: true });
  }
});
