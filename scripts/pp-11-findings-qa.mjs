#!/usr/bin/env node
/**
 * PP-11 /findings page QA — L1 data fidelity, L2 triage/export/retest, L3 browser matrix.
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

const EXPECTED_TABS = ['Open', 'By Target Group', 'By Vector', 'Accepted Risk', 'Closed', 'SLA'];

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

function countOpen(items = []) {
  return items.filter((finding) => finding.status === 'open').length;
}

function countAcceptedRisk(items = []) {
  return items.filter((finding) => finding.status === 'accepted_risk').length;
}

function countClosed30d(items = [], now = Date.now()) {
  return items.filter((finding) => {
    if (finding.status !== 'closed') return false;
    const updated = Date.parse(String(finding.updated_at ?? finding.created_at ?? ''));
    return Number.isFinite(updated) && now - updated <= 30 * 24 * 60 * 60 * 1000;
  }).length;
}

function countSlaBreach(items = [], now = Date.now()) {
  const SLA_HOURS = { critical: 24, high: 48, medium: 72, low: 168, info: 168 };
  return items.filter((finding) => {
    if (finding.status !== 'open') return false;
    const created = Date.parse(String(finding.created_at ?? ''));
    if (!Number.isFinite(created)) return false;
    const severity = String(finding.severity ?? 'low').toLowerCase();
    const hours = SLA_HOURS[severity] ?? 168;
    return now > created + hours * 60 * 60 * 1000;
  }).length;
}

async function ensureFindingFixture() {
  const existing = await api('GET', '/v1/findings');
  if (existing.status !== 200) {
    fail('l1', `GET /v1/findings failed (${existing.status})`);
    return null;
  }
  if ((existing.json?.items ?? []).length > 0) {
    note('l2', `reusing existing finding ${existing.json.items[0].id}`);
    return existing.json.items[0];
  }

  const [groups, targets] = await Promise.all([
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/target-groups/tg_demo')
  ]);
  const groupId = groups.json?.items?.[0]?.id ?? 'tg_demo';
  const targetId = targets.json?.targets?.[0]?.id;
  if (!targetId) fail('l2', 'no declared target for WAF finding fixture');

  let assetId = '';
  const assets = await api('GET', '/v1/waf/assets');
  if (assets.status === 200 && assets.json?.items?.[0]?.id) {
    assetId = assets.json.items[0].id;
  } else {
    const createdAsset = await api('POST', '/v1/waf/assets', {
      target_group_id: groupId,
      target_id: targetId,
      canonical_url: 'https://pp11-qa.example.com',
      owner_hint: 'pp11-qa'
    });
    if (createdAsset.status !== 201 || !createdAsset.json?.asset?.id) {
      fail('l2', `waf asset create failed (${createdAsset.status})`);
      return null;
    }
    assetId = createdAsset.json.asset.id;
  }

  const validation = await api('POST', '/v1/waf/validations', {
    waf_asset_id: assetId,
    modes: ['marker']
  });
  if (validation.status !== 201 || !validation.json?.validation_run?.id) {
    fail('l2', `waf validation create failed (${validation.status})`);
    return null;
  }

  const finalize = await api('POST', `/v1/waf/validations/${validation.json.validation_run.id}/finalize`, {
    waf_detected: true,
    validation_failed: true,
    scenario_results: [{
      scenario_family: 'marker',
      expected_action: 'block',
      observed_action: 'allow',
      passed: false,
      evidence_summary_json: { blocked: false }
    }]
  });
  if (finalize.status !== 200) {
    fail('l2', `waf validation finalize failed (${finalize.status})`);
    return null;
  }

  const findings = await api('GET', '/v1/findings');
  const finding = findings.json?.items?.[0] ?? null;
  if (!finding?.id) fail('l2', 'finding fixture not created');
  else note('l2', `created finding fixture ${finding.id}`);
  return finding;
}

async function runL1(fixture) {
  const [findings, state, checks] = await Promise.all([
    api('GET', '/v1/findings'),
    api('GET', '/v1/state'),
    api('GET', '/v1/checks')
  ]);

  if (findings.status !== 200) fail('l1', `GET /v1/findings failed (${findings.status})`);
  if (state.status !== 200) fail('l1', `GET /v1/state failed (${state.status})`);
  if (checks.status !== 200) fail('l1', `GET /v1/checks failed (${checks.status})`);

  const items = findings.json?.items ?? [];
  const now = Date.now();
  const derived = {
    openCount: countOpen(items),
    acceptedRiskCount: countAcceptedRisk(items),
    closed30dCount: countClosed30d(items, now),
    slaBreachCount: countSlaBreach(items, now)
  };

  note('l1', `findings=${items.length}`);
  note('l1', `open=${derived.openCount}`);
  note('l1', `accepted_risk=${derived.acceptedRiskCount}`);
  note('l1', `closed_30d=${derived.closed30dCount}`);
  note('l1', `sla_breach=${derived.slaBreachCount}`);

  if (state.json?.open_findings !== derived.openCount) {
    fail('l1', `open_findings mismatch state=${state.json?.open_findings} list=${derived.openCount}`);
  }

  if (fixture?.id) {
    const detail = await api('GET', `/v1/findings/${fixture.id}`);
    if (detail.status !== 200) fail('l1', `GET /v1/findings/${fixture.id} failed (${detail.status})`);
    else note('l1', `detail ok for ${fixture.id}`);
  }

  return { items, derived, checks: checks.json?.items ?? [], fixture };
}

async function runL2(fixture) {
  if (!fixture?.id) {
    fail('l2', 'no finding available for triage actions');
    return fixture;
  }

  const findingId = fixture.id;

  const assignee = await api('PATCH', `/v1/findings/${findingId}`, { assignee: 'pp11-qa-owner' });
  if (assignee.status !== 200 || assignee.json?.assignee !== 'pp11-qa-owner') {
    fail('l2', `PATCH assignee failed (${assignee.status})`);
  } else {
    note('l2', 'assignee patch ok');
  }

  const exported = await api('POST', `/v1/findings/${findingId}/export`);
  if (exported.status !== 200 || !exported.json?.custody) {
    fail('l2', `POST export failed (${exported.status})`);
  } else {
    note('l2', 'export with custody ok');
  }

  const accepted = await api('PATCH', `/v1/findings/${findingId}`, { status: 'accepted_risk' });
  if (accepted.status !== 200 || accepted.json?.status !== 'accepted_risk') {
    fail('l2', `PATCH accept-risk failed (${accepted.status})`);
  } else {
    note('l2', 'accept-risk ok');
  }

  const reopened = await api('PATCH', `/v1/findings/${findingId}`, { status: 'open' });
  if (reopened.status !== 200 || reopened.json?.status !== 'open') {
    fail('l2', `PATCH reopen failed (${reopened.status})`);
  } else {
    note('l2', 'reopen for close test ok');
  }

  const closed = await api('PATCH', `/v1/findings/${findingId}`, { status: 'closed' });
  if (closed.status !== 200 || closed.json?.status !== 'closed') {
    fail('l2', `PATCH close failed (${closed.status})`);
  } else {
    note('l2', 'close ok');
  }

  const restored = await api('PATCH', `/v1/findings/${findingId}`, { status: 'open' });
  if (restored.status !== 200 || restored.json?.status !== 'open') {
    fail('l2', `PATCH restore open failed (${restored.status})`);
  } else {
    note('l2', 'restored open for browser retest');
  }

  if (fixture.check_id?.startsWith('waf.posture.')) {
    const assetId = fixture.check_id.slice('waf.posture.'.length);
    const retest = await api('POST', '/v1/waf/validations', {
      waf_asset_id: assetId,
      modes: ['marker']
    });
    if (retest.status !== 201) fail('l2', `retest waf validation failed (${retest.status})`);
    else note('l2', 'retest waf validation ok');
  }

  return fixture;
}

async function ensurePlaywright() {
  try {
    return await import('playwright-core');
  } catch {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 120000
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core');
    return import('playwright-core');
  }
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

async function runL3(l1Fixture) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const { derived, fixture } = l1Fixture;

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      const findingsListResponse = page.waitForResponse(
        (res) => res.url().includes('/v1/findings') && res.request().method() === 'GET' && !res.url().includes('/export'),
        { timeout: 20000 }
      );
      await page.goto(`${BASE_URL}/app#findings`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await findingsListResponse;
      await page.waitForSelector('text=Findings', { timeout: 20000 });
      await page.waitForTimeout(1500);
      const bodyText = await page.locator('body').textContent() ?? '';

      const required = [
        'Findings',
        'Open findings',
        'Accepted risk',
        'Closed (30d)',
        'SLA breach',
        ...EXPECTED_TABS
      ];
      for (const snippet of required) {
        if (!bodyText.includes(snippet)) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }

      const openMetricCard = page.locator('.metric-card', { hasText: 'Open findings' }).first();
      const openMetric = await openMetricCard.locator('strong').innerText();
      if (openMetric !== String(derived.openCount)) {
        fail('l1', `${viewport.name}: open findings metric mismatch (expected ${derived.openCount}, got ${openMetric})`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (consoleErrors.filter((e) => !/favicon/i.test(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      if (viewport.name === 'desktop' && fixture?.id) {
        const findingsTabs = page.locator('.tabs-wrap').first();
        for (const tab of EXPECTED_TABS) {
          await findingsTabs.getByRole('tab', { name: tab, exact: true }).click();
          await page.waitForTimeout(500);
          const selected = await findingsTabs.getByRole('tab', { name: tab, exact: true }).getAttribute('aria-selected');
          if (selected !== 'true') fail('l2', `tab "${tab}" not selected after click`);
          if (tab === 'By Vector' && derived.openCount > 0) {
            const vectorHeader = await page.locator('th', { hasText: 'Vector' }).count();
            if (!vectorHeader) fail('l2', 'By Vector tab missing Vector column header');
          }
          if (tab === 'SLA' && derived.openCount > 0) {
            const slaHeader = await page.locator('th', { hasText: 'SLA' }).count();
            if (!slaHeader) fail('l2', 'SLA tab missing SLA column header');
          }
          note('l2', `tab ${tab} renders`);
        }

        if (derived.openCount > 0) {
          await findingsTabs.getByRole('tab', { name: 'Open', exact: true }).click();
          await page.waitForTimeout(400);
          const detailBtn = page.getByRole('button', { name: 'Detail' }).first();
          if (await detailBtn.count()) {
            let detailText = await page.locator('body').textContent() ?? '';
            if (!detailText.includes('Why this finding?') && !detailText.includes('Triage and assignee')) {
              const detailResponse = page.waitForResponse(
                (res) => res.url().includes(`/v1/findings/${fixture.id}`) && res.request().method() === 'GET',
                { timeout: 15000 }
              );
              await detailBtn.click();
              await detailResponse.catch(() => undefined);
              await page.waitForTimeout(800);
              detailText = await page.locator('body').textContent() ?? '';
            }
            if (!detailText.includes('Why this finding?')) fail('l2', 'detail panel missing verdict explanation');
            if (!detailText.includes('Triage and assignee')) fail('l2', 'detail triage panel missing');
            if (!detailText.includes('Export with custody')) fail('l2', 'detail export control missing');
            note('l2', 'browser detail + triage controls ok');
          } else {
            fail('l2', 'Detail button missing despite open findings');
          }
        }
      }

      note('l3', `${viewport.name}: findings render ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close().catch(() => undefined);
}

async function main() {
  const fixture = await ensureFindingFixture();
  const l1Fixture = await runL1(fixture);
  await runL2(fixture);
  await runL3(l1Fixture);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-11');
  console.log(`VERDICT: ${verdict}`);
  console.log(`L1: ${results.l1.pass ? 'PASS' : 'FAIL'} — ${results.l1.notes.join('; ')}`);
  console.log(`L2: ${results.l2.pass ? 'PASS' : 'FAIL'} — ${results.l2.notes.join('; ')}`);
  console.log(`L3: ${results.l3.pass ? 'PASS' : 'FAIL'} — ${results.l3.notes.join('; ')}`);
  if (results.failures.length) {
    console.log('FAILURES:');
    for (const failure of results.failures) console.log(`- [${failure.layer}] ${failure.detail}`);
  }
  setImmediate(() => process.exit(verdict === 'PASS' ? 0 : 1));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});