#!/usr/bin/env node
/**
 * PP-06 L1–L3 QA: /target-groups + #target-group-detail
 * Uses role=tab for detail tabs (not sidebar nav buttons with the same labels).
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const baseUrl = (process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320').replace(/\/$/, '');

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 820, height: 1180 },
  { name: 'mobile', width: 390, height: 844 },
];

const DEMO_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_pp06_browser',
  'x-role': 'engineer',
  'Content-Type': 'application/json',
};

function ensurePlaywrightCore() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (check.status !== 0) {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT,
      stdio: 'inherit',
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core');
  }
}

async function main() {
  ensurePlaywrightCore();
  const { chromium } = await import('playwright-core');

  const listRes = await fetch(`${baseUrl}/v1/target-groups`, { headers: DEMO_HEADERS });
  const listJson = await listRes.json();
  const groupId = listJson.items?.[0]?.id;
  if (!groupId) throw new Error('no seeded target group');

  const detailRes = await fetch(`${baseUrl}/v1/target-groups/${groupId}`, { headers: DEMO_HEADERS });
  const detailJson = await detailRes.json();

  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const failures = [];

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    await page.addInitScript(() => {
      sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
        mode: 'dev-headers',
        principal: 'customer',
        tenant_id: 'ten_demo',
        user_id: 'usr_pp06_browser',
        role: 'engineer',
      }));
    });

    const listLabel = `${viewport.name}:target-groups`;
    try {
      await page.goto(`${baseUrl}/app#target-groups`, { waitUntil: 'networkidle', timeout: 45000 });
      const body = await page.locator('body').innerText();
      for (const snippet of ['Create group', 'Add target', 'Save settings', 'Declared target groups']) {
        if (!body.includes(snippet)) failures.push({ step: listLabel, detail: `missing: ${snippet}` });
      }
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) failures.push({ step: listLabel, detail: 'horizontal overflow' });
    } catch (err) {
      failures.push({ step: listLabel, detail: String(err) });
    }

    const detailLabel = `${viewport.name}:target-group-detail`;
    try {
      await page.goto(`${baseUrl}/app#target-group-detail?id=${encodeURIComponent(groupId)}`, {
        waitUntil: 'networkidle',
        timeout: 45000,
      });
      const body = await page.locator('body').innerText();
      for (const snippet of ['Group summary', 'Declared targets', 'Expected Behavior', detailJson.name]) {
        if (!body.includes(snippet)) failures.push({ step: detailLabel, detail: `missing: ${snippet}` });
      }

      const tabList = page.locator('main .tabs-wrap[role="tablist"]');
      for (const tabName of ['Agents', 'Checks', 'Findings', 'Settings']) {
        const tab = tabList.getByRole('tab', { name: tabName, exact: true });
        if (await tab.count() === 0) {
          failures.push({ step: detailLabel, detail: `missing tab: ${tabName}` });
          continue;
        }
        await tab.click({ timeout: 10000 });
        await page.waitForTimeout(200);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) failures.push({ step: detailLabel, detail: 'horizontal overflow' });
    } catch (err) {
      failures.push({ step: detailLabel, detail: String(err) });
    }

    await context.close();
  }

  await browser.close();

  console.log('L1 API group count:', listJson.items.length, 'detail name:', detailJson.name);
  if (failures.length) {
    console.error('PP-06 L3 FAILURES:');
    for (const f of failures) console.error(` - ${f.step}: ${f.detail}`);
    process.exit(1);
  }
  console.log('PAGE QA PP-06');
  console.log('VERDICT: PASS');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});