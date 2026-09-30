#!/usr/bin/env node
/**
 * PP-03 /dashboard page QA — L1 data fidelity, L2 drilldown links, L3 browser matrix.
 *
 * Aligned to ADR-0008 (outside-in only, targets-first). The dashboard has two tabs —
 * Overview and Risk trends — and no agents, environments, "Business Services", or
 * "Evidence Feed" surfaces. `/v1/state` no longer exposes agents_online.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE_URL = process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320';

const HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_admin',
  'x-role': 'admin',
  'Content-Type': 'application/json'
};

const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'tablet', width: 820, height: 1180 },
  { name: 'mobile', width: 390, height: 844 }
];

const results = {
  l1: { pass: true, notes: [] },
  l2: { pass: true, notes: [] },
  l3: { pass: true, notes: [] },
  failures: []
};

function fail(layer, detail) {
  results[layer].pass = false;
  results.failures.push({ layer, detail });
}

function note(layer, detail) {
  results[layer].notes.push(detail);
}

async function api(method, route, body, headers = HEADERS) {
  const res = await fetch(`${BASE_URL}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

function countActiveTargetGroups(items = []) {
  return items.filter((group) => !group.archived_at).length;
}

function countOpenFindings(items = []) {
  return items.filter((finding) => (finding.status ?? finding.state ?? '').toLowerCase() === 'open').length;
}

async function runL1() {
  const [state, groups, findings, hs, runs, targets] = await Promise.all([
    api('GET', '/v1/state'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/findings'),
    api('GET', '/v1/high-scale-requests'),
    api('GET', '/v1/test-runs'),
    api('GET', '/v1/targets')
  ]);

  if (state.status !== 200) fail('l1', `GET /v1/state failed (${state.status})`);

  // ADR-0008: agents are removed. The state payload must not expose agent counts.
  if (state.json && Object.prototype.hasOwnProperty.call(state.json, 'agents_online')) {
    fail('l1', 'state.agents_online must be removed (ADR-0008 outside-in only)');
  } else {
    note('l1', 'no agents_online field (outside-in)');
  }

  const derived = {
    target_groups: countActiveTargetGroups(groups.json?.items),
    open_findings: countOpenFindings(findings.json?.items),
    high_scale_requests: (hs.json?.items ?? []).length
  };

  const pairs = [
    ['target_groups', state.json?.target_groups, derived.target_groups],
    ['open_findings', state.json?.open_findings, derived.open_findings],
    ['high_scale_requests', state.json?.high_scale_requests, derived.high_scale_requests]
  ];

  for (const [label, apiValue, listValue] of pairs) {
    if (apiValue !== undefined && apiValue !== listValue) {
      fail('l1', `${label}: state=${apiValue} list-derived=${listValue}`);
    } else {
      note('l1', `${label}=${apiValue ?? listValue}`);
    }
  }

  // Targets are first-class and expose top-level tags[].
  const firstTarget = targets.json?.items?.[0];
  if (firstTarget && !Array.isArray(firstTarget.tags)) {
    fail('l1', 'target payload must expose top-level tags[] (ADR-0008)');
  } else if (firstTarget) {
    note('l1', `targets expose tags[] (${targets.json.items.length} targets)`);
  }

  if (typeof state.json?.readiness?.score !== 'number') {
    note('l1', 'readiness.score not numeric — dashboard shows "not measured" state');
  } else {
    note('l1', `readiness.score=${state.json.readiness.score}`);
  }

  const recentRunIds = (state.json?.recent_runs ?? []).map((run) => run.id);
  const latestRuns = [...(runs.json?.items ?? [])].slice(-5).map((run) => run.id);
  if (recentRunIds.length && latestRuns.length && recentRunIds[recentRunIds.length - 1] !== latestRuns[latestRuns.length - 1]) {
    fail('l1', `recent_runs tail mismatch state=${recentRunIds.join(',')} runs=${latestRuns.join(',')}`);
  } else {
    note('l1', `recent_runs count=${recentRunIds.length}`);
  }
}

async function ensurePlaywright() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (check.status !== 0) {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT,
      encoding: 'utf8'
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core');
  }
  return import('playwright-core');
}

async function injectSession(page) {
  await page.goto(`${BASE_URL}/app`, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.evaluate(() => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: 'ten_demo',
      user_id: 'usr_admin',
      role: 'admin'
    }));
  });
}

async function runL2L3() {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const [state, runs] = await Promise.all([
    api('GET', '/v1/state'),
    api('GET', '/v1/test-runs')
  ]);
  const runId = state.json?.recent_runs?.[0]?.id ?? runs.json?.items?.slice(-1)?.[0]?.id ?? '';

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#dashboard`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(1500);
      const bodyText = await page.locator('body').innerText();
      const normalizedBody = bodyText.toLowerCase();

      // New outside-in dashboard surfaces (Overview tab).
      const required = ['where does attack traffic get stopped?', 'declared targets', 'evidence coverage', 'open findings', 'target posture', 'recent validation activity'];
      for (const snippet of required) {
        if (!normalizedBody.includes(snippet.toLowerCase())) fail('l3', `${viewport.name}: missing "${snippet}"`);
      }

      // Removed features must never appear.
      for (const forbidden of ['agents online', 'agents healthy', 'environment status', 'business services', 'evidence feed']) {
        if (normalizedBody.includes(forbidden)) fail('l3', `${viewport.name}: removed feature present "${forbidden}"`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (consoleErrors.length) fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      if (viewport.name === 'desktop') {
        // Recent validation activity row drilldown.
        if (runId) {
          const runLink = page.locator(`a[href*="run-detail"][href*="${runId}"]`).first();
          const runRow = page.locator(`[aria-label*="${runId}"]`).first();
          if (await runLink.count()) {
            await runLink.click();
          } else if (await runRow.count()) {
            await runRow.click();
          } else {
            note('l2', `no run drilldown target for ${runId} (may be empty demo)`);
          }
          await page.waitForTimeout(800);
          if (page.url().includes('run-detail') || (await page.locator('body').innerText()).includes(runId)) {
            note('l2', `run drilldown ok (${runId})`);
          }
          await page.goto(`${BASE_URL}/app#dashboard`, { waitUntil: 'networkidle', timeout: 45000 });
        }

        // Risk trends tab renders its hero and matrices.
        await page.getByRole('tab', { name: 'Risk trends' }).click();
        await page.waitForTimeout(500);
        const riskText = await page.locator('body').innerText();
        for (const marker of ['Readiness trend', 'Vector coverage matrix', 'Resource exhaustion matrix']) {
          if (!riskText.includes(marker)) fail('l2', `Risk trends tab missing "${marker}"`);
          else note('l2', `Risk trends renders ${marker}`);
        }
      }

      note('l3', `${viewport.name}: dashboard render ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  await runL1();
  await runL2L3();

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-03');
  console.log(`VERDICT: ${verdict}`);
  console.log(`L1: ${results.l1.pass ? 'PASS' : 'FAIL'} — ${results.l1.notes.join('; ')}`);
  console.log(`L2: ${results.l2.pass ? 'PASS' : 'FAIL'} — ${results.l2.notes.join('; ')}`);
  console.log(`L3: ${results.l3.pass ? 'PASS' : 'FAIL'} — ${results.l3.notes.join('; ')}`);
  if (results.failures.length) {
    console.log('FAILURES:');
    for (const failure of results.failures) console.log(`- [${failure.layer}] ${failure.detail}`);
  }
  process.exit(verdict === 'PASS' ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
