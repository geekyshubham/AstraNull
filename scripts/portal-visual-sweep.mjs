#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { applyPortalBaselineReadinessBoost } from '../tests/fixtures/portal-baseline/readiness.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer } from '../tests/helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, gotoPublicPortalRoute, injectPortalSessionForSurface } from '../tests/helpers/portal-playwright-session.mjs';
import { ROUTES_TO_SCAN } from '../tests/helpers/portal-routes.mjs';

const OUT = path.resolve(process.argv[2] ?? 'output/visual-sweep');
const ONLY = process.argv[3] ? new Set(process.argv[3].split(',')) : null;
const VIEWPORTS = [
  { name: 'mobile', width: 375, height: 812, touch: true },
  { name: 'tablet', width: 768, height: 1024, touch: true },
  { name: 'desktop', width: 1440, height: 900 },
];
const THEMES = ['dark', 'light'];
const VARIANT_ROUTES = new Set(['runs', 'findings', 'test-policies']);

const routes = [];
for (const entry of ROUTES_TO_SCAN) {
  routes.push({ ...entry, variant: null });
  if (VARIANT_ROUTES.has(entry.routeId)) routes.push({ ...entry, variant: 'refined' });
}

function geometryProbe() {
  const vw = document.documentElement.clientWidth;
  const issues = { pageOverflowX: document.documentElement.scrollWidth - vw, offscreen: [], smallTargets: [], clippedText: [], overlaps: [] };
  const label = (el) => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${el.classList.length ? `.${[...el.classList].slice(0, 3).join('.')}` : ''} "${(el.getAttribute('aria-label') || el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40)}"`;
  const inScroller = (el) => {
    for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (/(auto|scroll|hidden|clip)/.test(s.overflowX) && p.scrollWidth > p.clientWidth + 1) return true;
    }
    return false;
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0;
  };
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    if ((r.right > vw + 1 || r.left < -1) && !inScroller(el) && getComputedStyle(el).position !== 'fixed') {
      if (issues.offscreen.length < 15) issues.offscreen.push(`${label(el)} [${Math.round(r.left)}..${Math.round(r.right)}]`);
    }
  }
  const interactive = document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea, [role=button], [role=tab], [role=link], [role=checkbox], [role=switch], summary');
  for (const el of interactive) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    const inline = el.tagName === 'A' && getComputedStyle(el).display === 'inline';
    if (!inline && (r.width < 44 || r.height < 44) && issues.smallTargets.length < 25) {
      issues.smallTargets.push(`${label(el)} ${Math.round(r.width)}x${Math.round(r.height)}`);
    }
  }
  for (const el of document.querySelectorAll('h1,h2,h3,h4,p,span,td,th,label,button,a,dt,dd,li,strong,code')) {
    if (!visible(el) || !el.childNodes.length) continue;
    const s = getComputedStyle(el);
    if (s.textOverflow === 'ellipsis') continue;
    if ((s.overflowX === 'hidden' || s.overflow === 'hidden' || s.overflowX === 'clip') && el.scrollWidth > el.clientWidth + 2 && issues.clippedText.length < 15) {
      issues.clippedText.push(`${label(el)} ${el.scrollWidth}>${el.clientWidth}`);
    }
  }
  return issues;
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
          page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 200)); });
          page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${String(err).slice(0, 200)}`));
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
            entry.appliedTheme = await page.evaluate(() => document.documentElement.dataset.theme ?? 'unset');
            entry.geometry = await page.evaluate(geometryProbe);
            if (vp.name !== 'tablet') {
              const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']).analyze();
              entry.axe = axe.violations.map((v) => ({ id: v.id, impact: v.impact, count: v.nodes.length, targets: v.nodes.slice(0, 4).map((n) => `${n.target.join(' ')} :: ${(n.failureSummary || '').split('\n').slice(1, 2).join(' ').slice(0, 160)}`) }));
            }
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
          entry.consoleErrors = consoleErrors.slice(0, 5);
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
}

main().catch((error) => { console.error(error); process.exit(1); });
