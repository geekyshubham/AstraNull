#!/usr/bin/env node
/**
 * PP-03 /dashboard page QA — L1 data fidelity, L2 drilldown links, L3 browser matrix.
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

function countAgentsOnline(items = []) {
  return items.filter((agent) => agent.status === 'online').length;
}

function countOpenFindings(items = []) {
  return items.filter((finding) => finding.status === 'open').length;
}

async function runL1() {
  const [state, agents, groups, findings, hs, runs] = await Promise.all([
    api('GET', '/v1/state'),
    api('GET', '/v1/agents'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/findings'),
    api('GET', '/v1/high-scale-requests'),
    api('GET', '/v1/test-runs')
  ]);

  if (state.status !== 200) fail('l1', `GET /v1/state failed (${state.status})`);

  const derived = {
    target_groups: countActiveTargetGroups(groups.json?.items),
    agents_online: countAgentsOnline(agents.json?.items),
    open_findings: countOpenFindings(findings.json?.items),
    high_scale_requests: (hs.json?.items ?? []).length
  };

  const pairs = [
    ['target_groups', state.json?.target_groups, derived.target_groups],
    ['agents_online', state.json?.agents_online, derived.agents_online],
    ['open_findings', state.json?.open_findings, derived.open_findings],
    ['high_scale_requests', state.json?.high_scale_requests, derived.high_scale_requests],
    ['agents_online vs agents.items online', state.json?.agents_online, countAgentsOnline(agents.json?.items)]
  ];

  for (const [label, apiValue, listValue] of pairs) {
    if (apiValue !== listValue) {
      fail('l1', `${label}: state=${apiValue} list-derived=${listValue}`);
    } else {
      note('l1', `${label}=${apiValue}`);
    }
  }

  if (typeof state.json?.readiness?.score !== 'number') {
    fail('l1', 'readiness.score missing or not a number');
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

  const [state, groups, runs] = await Promise.all([
    api('GET', '/v1/state'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/test-runs')
  ]);
  const metrics = {
    targetGroups: state.json?.target_groups,
    agentsOnline: state.json?.agents_online,
    openFindings: state.json?.open_findings,
    highScale: state.json?.high_scale_requests,
    score: state.json?.readiness?.score
  };
  const runId = state.json?.recent_runs?.[0]?.id ?? runs.json?.items?.slice(-1)?.[0]?.id ?? '';
  const groupId = groups.json?.items?.[0]?.id ?? '';

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

      if (typeof metrics.score === 'number' && !bodyText.toLowerCase().includes('readiness score')) {
        fail('l1', `${viewport.name}: readiness score card missing`);
      }

      const required = ['Readiness score', 'target groups', 'agents online', 'open findings', 'Recent test runs', 'Business Services', 'Risk Trends', 'Evidence Feed'];
      const normalizedBody = bodyText.toLowerCase();
      for (const snippet of required) {
        if (!normalizedBody.includes(snippet.toLowerCase())) fail('l3', `${viewport.name}: missing "${snippet}"`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (consoleErrors.length) fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      if (viewport.name === 'desktop') {
        if (runId) {
          const runLink = page.locator(`a[href*="run-detail"][href*="${runId}"]`).first();
          if (await runLink.count()) {
            await runLink.click();
            await page.waitForTimeout(800);
            if (!page.url().includes('run-detail') && !(await page.locator('body').innerText()).includes(runId)) {
              fail('l2', `run drilldown failed for ${runId}`);
            } else {
              note('l2', `run drilldown ok (${runId})`);
            }
            await page.goto(`${BASE_URL}/app#dashboard`, { waitUntil: 'networkidle', timeout: 45000 });
          } else {
            fail('l2', `missing run drilldown link for ${runId}`);
          }
        }

        for (const [tab, marker] of [
          ['Business Services', 'Business services'],
          ['Risk Trends', 'Readiness trend'],
          ['Evidence Feed', 'Evidence feed']
        ]) {
          await page.getByRole('tab', { name: tab }).click();
          await page.waitForTimeout(500);
          const tabText = await page.locator('body').innerText();
          if (!tabText.includes(marker)) fail('l2', `tab "${tab}" missing content "${marker}"`);
          else note('l2', `tab ${tab} renders ${marker}`);
        }

        if (groupId) {
          await page.getByRole('tab', { name: 'Business Services' }).click();
          await page.waitForTimeout(400);
          const groupLink = page.locator(`a[href*="target-group-detail"][href*="${groupId}"]`).first();
          if (await groupLink.count()) {
            await groupLink.click();
            await page.waitForTimeout(800);
            const detailText = await page.locator('body').innerText();
            if (!detailText.includes('Group summary') && !detailText.includes(groupId)) {
              fail('l2', `target-group drilldown failed for ${groupId}`);
            } else {
              note('l2', `target-group drilldown ok (${groupId})`);
            }
          }
        }

        const findingsLink = page.locator('a[href="#findings"]').first();
        if (await findingsLink.count()) {
          await page.goto(`${BASE_URL}/app#dashboard`, { waitUntil: 'networkidle', timeout: 45000 });
          await findingsLink.click();
          await page.waitForTimeout(800);
          if (!(await page.locator('body').innerText()).toLowerCase().includes('findings')) {
            fail('l2', 'findings drilldown failed');
          } else {
            note('l2', 'findings drilldown ok');
          }
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