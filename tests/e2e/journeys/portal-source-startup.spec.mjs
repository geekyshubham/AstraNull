import { expect, test } from '@playwright/test';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createViteServer } from 'vite';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
test.describe.configure({ mode: 'default', retries: 0 });

for (const arm of ['cold', 'shared-overlap', 'isolated-overlap', 'aligned-define', 'explicit-includes']) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    test(`source first navigation ${arm} attempt ${attempt}`, async ({ browser }, testInfo) => {
      test.setTimeout(240_000);
      const owned = await mkdtemp(path.join(os.tmpdir(), 'astranull-source-startup-'));
      const servers = [];
      const pages = [];
      const report = { arm, attempt, owned, nodeEnv: process.env.NODE_ENV, servers: [], loads: [] };
      try {
        const { baseUrl: apiBase } = await startPortalPlaywrightServer();
        async function start(cacheDir, mode, hmr) {
          const server = await createViteServer({
            configFile: path.join(root, 'vite.config.ts'),
            root: path.join(root, 'apps/web/react'), cacheDir, mode, logLevel: 'error',
            ...(arm === 'aligned-define' ? { define: { 'process.env.NODE_ENV': JSON.stringify('development') } } : {}),
            ...(arm === 'explicit-includes' ? { optimizeDeps: { include: ['react', 'react-dom', 'react-dom/client', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'lucide-react', 'clsx', 'tailwind-merge', 'class-variance-authority'] } } : {}),
            server: { host: '127.0.0.1', port: 0, strictPort: false, hmr,
              proxy: { '/v1': apiBase, '/ready': apiBase, '/internal': apiBase } },
          });
          servers.push(server);
          await server.listen();
          const url = `http://127.0.0.1:${server.httpServer.address().port}`;
          report.servers.push({ url, cacheDir: server.config.cacheDir, mode: server.config.mode,
            define: server.config.define, nodeEnv: process.env.NODE_ENV, hmr });
          return { server, url };
        }
        async function load(source) {
          const page = await browser.newPage();
          pages.push(page);
          await injectPortalDevHeadersSession(page);
          const loadReport = { url: source.url, failures: [], modules: [] };
          report.loads.push(loadReport);
          let diagnostics;
          try {
            diagnostics = await assertPortalInitialLoad(page, source.url, { onDiagnostics(value) { diagnostics = value; loadReport.failures = value.failures; } });
            await expect(page.locator('#portal-main h1')).toHaveText('Readiness overview');
          } finally {
            loadReport.modules = [...(diagnostics?.modules ?? [])];
            const reactUrls = loadReport.modules.filter((url) => /\/react\.js\?/.test(url));
            if (reactUrls.length > 1) {
              loadReport.reactIdentity = await page.evaluate(async (urls) => {
                const modules = await Promise.all(urls.map((url) => import(url)));
                return { urls, sameInstance: modules.every((module) => module.default === modules[0].default) };
              }, reactUrls).catch((error) => ({ unavailable: error.message }));
            }
            const metadata = path.join(source.server.config.cacheDir, 'deps', '_metadata.json');
            loadReport.optimizer = await readFile(metadata, 'utf8').then(JSON.parse).catch((error) => ({ unavailable: error.code }));
          }
          return page;
        }
        const first = await start(path.join(owned, 'first'), 'development', false);
        await load(first);
        if (['shared-overlap', 'isolated-overlap'].includes(arm)) {
          const second = await start(path.join(owned, arm === 'shared-overlap' ? 'first' : 'second'), 'test', true);
          // The first page has completed optimizer delivery before the second server may replace its cache.
          await load(second);
          await load(first);
        }
      } finally {
        await writeFile(path.join(owned, 'startup-module-identity.json'), JSON.stringify(report, null, 2));
        console.log(`startup diagnostic: ${path.join(owned, 'startup-module-identity.json')}`);
        await testInfo.attach('startup-module-identity', { body: JSON.stringify(report, null, 2), contentType: 'application/json' });
        await Promise.all(pages.map((page) => page.close()));
        for (const server of servers.reverse()) await server.close();
        await stopPortalPlaywrightServer();
      }
    });
  }
}
