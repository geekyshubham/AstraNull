#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { applyPortalBaselineReadinessBoost } from '../tests/fixtures/portal-baseline/readiness.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../tests/helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, gotoPublicPortalRoute, injectPortalSessionForSurface } from '../tests/helpers/portal-playwright-session.mjs';
import { ROUTES_TO_SCAN } from '../tests/helpers/portal-routes.mjs';
import { portalGeometryProbe, visualSweepFailures } from './lib/portal-visual-results.mjs';

const OUT = path.resolve(process.argv[2] ?? 'output/visual-sweep');
const ONLY = process.argv[3] ? new Set(process.argv[3].split(',')) : null;
const VIEWPORTS = [
  { name: 'mobile', width: 375, height: 812, touch: true },
  { name: 'tablet', width: 768, height: 1024, touch: true },
  { name: 'laptop', width: 1024, height: 768 },
  { name: 'desktop', width: 1440, height: 900 },
];
const THEMES = ['dark', 'light'];
const VARIANT_ROUTES = new Set(['targets', 'runs', 'findings', 'test-policies']);

const routes = [];
for (const entry of ROUTES_TO_SCAN) {
  routes.push({ ...entry, variant: null });
  if (VARIANT_ROUTES.has(entry.routeId)) routes.push({ ...entry, variant: 'refined' });
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const { baseUrl } = await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  const browser = await chromium.launch({ headless: true });
  const report = [];
  try {
    for (const route of routes) {
      const key = `${route.routeId}${route.variant ? `--${route.variant}` : ''}`;
      if (ONLY && !ONLY.has(key) && !ONLY.has(route.routeId)) continue;
      for (const theme of THEMES) {
        for (const vp of VIEWPORTS) {
          const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, hasTouch: Boolean(vp.touch), isMobile: Boolean(vp.touch), reducedMotion: 'reduce' });
          const page = await context.newPage();
          const consoleErrors = [];
          const diagnostics = [];
          let phase = 'navigation';
          page.on('console', (msg) => {
            if (msg.type() !== 'error') return;
            const message = msg.text();
            consoleErrors.push(message);
            diagnostics.push({ phase, kind: 'console', message, location: msg.location(), classification: phase === 'axe' && /fonts\.googleapis\.com/.test(message) && /connect-src/.test(message) ? 'audit_stylesheet_csp_refetch' : 'unclassified' });
          });
          page.on('pageerror', (err) => {
            const message = String(err);
            consoleErrors.push(`pageerror: ${message}`);
            diagnostics.push({ phase, kind: 'pageerror', message, classification: 'unclassified' });
          });
          await page.addInitScript((t) => { try { localStorage.setItem('astranull.theme', t); } catch {} }, theme);
          if (route.variant) {
            await page.addInitScript(([r, v]) => { try { localStorage.setItem(`astranull.design-variant.${r}`, v); } catch {} }, [route.routeId, route.variant]);
          }
          await injectPortalSessionForSurface(page, route.surface);
          const entry = { route: key, theme, viewport: vp.name };
          try {
            if (route.surface === 'public') await gotoPublicPortalRoute(page, route.pathname, baseUrl);
            else await gotoPortalRoute(page, route.routeId, baseUrl);
            await page.waitForTimeout(400);
            entry.themeAttribute = await page.evaluate(() => document.documentElement.dataset.theme ?? null);
            entry.appliedTheme = entry.themeAttribute ?? 'dark';
            if (entry.appliedTheme !== theme) throw new Error(`Requested ${theme} theme but rendered ${entry.appliedTheme}`);
            entry.geometry = await page.evaluate(portalGeometryProbe);
            entry.axeStatus = vp.name === 'tablet' ? 'not_run_tablet' : 'running';
            if (vp.name !== 'tablet') {
              phase = 'axe';
              const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']).analyze();
              entry.axe = axe.violations.map((v) => ({ id: v.id, impact: v.impact, count: v.nodes.length, targets: v.nodes.slice(0, 4).map((n) => `${n.target.join(' ')} :: ${(n.failureSummary || '').split('\n').slice(1, 2).join(' ').slice(0, 160)}`) }));
              entry.axeStatus = 'completed';
            }
            phase = 'post_audit';
            const shot = path.join(OUT, `${key}.${theme}.${vp.name}.png`);
            if (vp.touch) {
              let height = vp.height;
              for (let pass = 0; pass < 4; pass += 1) {
                const fullHeight = Math.min(await page.evaluate(() => document.documentElement.scrollHeight), 16000);
                if (fullHeight <= height) break;
                height = fullHeight;
                await page.setViewportSize({ width: vp.width, height });
                await page.waitForTimeout(150);
              }
              await page.screenshot({ path: shot });
            } else {
              await page.screenshot({ path: shot, fullPage: true });
            }
          } catch (error) {
            entry.error = String(error).slice(0, 300);
          }
          entry.renderingFixture = 'system_font_fallbacks_not_real_google_fonts';
          entry.consoleErrors = consoleErrors;
          entry.diagnostics = diagnostics;
          report.push(entry);
          await context.close();
          process.stdout.write('.');
        }
      }
    }
  } finally {
    await browser.close();
    await stopPortalPlaywrightServer();
  }
  writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 2));
  console.log(`\nwrote ${report.length} entries to ${OUT}`);
  const failures = visualSweepFailures(report);
  if (failures.length) {
    console.error(failures.join('\n'));
    process.exitCode = 1;
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
