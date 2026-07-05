#!/usr/bin/env node
/**
 * PP-09 /test-policies page QA — L1 data fidelity, L2 create/patch/archive, L3 browser matrix.
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

async function runL1() {
  const [policies, checks, groups] = await Promise.all([
    api('GET', '/v1/test-policies'),
    api('GET', '/v1/checks'),
    api('GET', '/v1/target-groups')
  ]);

  if (policies.status !== 200) fail('l1', `GET /v1/test-policies failed (${policies.status})`);
  if (checks.status !== 200) fail('l1', `GET /v1/checks failed (${checks.status})`);
  if (groups.status !== 200) fail('l1', `GET /v1/target-groups failed (${groups.status})`);

  const policyItems = policies.json?.items ?? [];
  const checkItems = checks.json?.items ?? [];
  const safeChecks = checkItems.filter((check) => check.safety_class === 'safe');
  const socGatedChecks = checkItems.filter((check) => check.safety_class === 'soc_gated');

  note('l1', `active_policies=${policyItems.length}`);
  note('l1', `safe_checks=${safeChecks.length}`);
  note('l1', `soc_gated_checks=${socGatedChecks.length}`);

  for (const policy of policyItems) {
    if (!policy.target_group || typeof policy.target_group !== 'object') {
      fail('l1', `policy ${policy.id} missing enriched target_group`);
    }
    if (!policy.check || typeof policy.check !== 'object') {
      fail('l1', `policy ${policy.id} missing enriched check metadata`);
    }
    if (policy.check?.safety_class !== 'safe') {
      fail('l1', `policy ${policy.id} bound to non-safe check ${policy.check_id}`);
    }
    if (typeof policy.target_count !== 'number') {
      fail('l1', `policy ${policy.id} missing target_count`);
    }
  }

  return {
    policyItems,
    safeChecks,
    socGatedChecks,
    targetGroupId: groups.json?.items?.[0]?.id ?? '',
    safeCheckId: safeChecks[0]?.check_id ?? 'dns.authoritative_response.safe'
  };
}

async function runL2(fixture) {
  const { targetGroupId, safeCheckId } = fixture;
  if (!targetGroupId) {
    fail('l2', 'no target group available for policy create');
    return null;
  }

  const created = await api('POST', '/v1/test-policies', {
    target_group_id: targetGroupId,
    check_id: safeCheckId,
    cadence: 'daily',
    expected_verdict: 'pass',
    safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }]
  });
  if (created.status !== 201 || !created.json?.id) {
    fail('l2', `POST /v1/test-policies failed (${created.status})`);
    return null;
  }
  const policyId = created.json.id;
  note('l2', `created policy ${policyId}`);

  const paused = await api('PATCH', `/v1/test-policies/${policyId}`, { state: 'paused' });
  if (paused.status !== 200 || paused.json?.state !== 'paused') {
    fail('l2', `PATCH pause failed (${paused.status}) state=${paused.json?.state}`);
  } else {
    note('l2', 'pause ok');
  }

  const resumed = await api('PATCH', `/v1/test-policies/${policyId}`, { state: 'active' });
  if (resumed.status !== 200 || resumed.json?.state !== 'active') {
    fail('l2', `PATCH resume failed (${resumed.status}) state=${resumed.json?.state}`);
  } else {
    note('l2', 'resume ok');
  }

  const weekly = await api('PATCH', `/v1/test-policies/${policyId}`, { cadence: 'weekly' });
  if (weekly.status !== 200 || weekly.json?.cadence !== 'weekly') {
    fail('l2', `PATCH cadence failed (${weekly.status}) cadence=${weekly.json?.cadence}`);
  } else {
    note('l2', 'cadence weekly ok');
  }

  const archived = await api('DELETE', `/v1/test-policies/${policyId}`);
  if (archived.status !== 200 || archived.json?.archived !== true) {
    fail('l2', `DELETE archive failed (${archived.status})`);
  } else {
    note('l2', 'archive ok');
  }

  const listed = await api('GET', '/v1/test-policies');
  if ((listed.json?.items ?? []).some((item) => item.id === policyId)) {
    fail('l2', `archived policy ${policyId} still listed`);
  } else {
    note('l2', 'archived policy omitted from list');
  }

  const socReject = await api('POST', '/v1/test-policies', {
    target_group_id: targetGroupId,
    check_id: 'high_scale.volumetric.request_only',
    cadence: 'manual'
  });
  if (socReject.status !== 403 || socReject.json?.error !== 'soc_gated_check') {
    fail('l2', `SOC-gated rejection expected 403 soc_gated_check got ${socReject.status}`);
  } else {
    note('l2', 'soc_gated_check rejection ok');
  }

  return policyId;
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

async function runL3(fixture) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const { policyItems, safeChecks, socGatedChecks, targetGroupId, safeCheckId } = fixture;

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.reload({ waitUntil: 'networkidle', timeout: 45000 });
      await page.goto(`${BASE_URL}/app#test-policies`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForSelector('.metric-card', { timeout: 20000 });
      await page.waitForTimeout(800);
      const bodyText = await page.locator('body').innerText();

      const required = [
        'Test Policies',
        'Active policies',
        'Safe checks',
        'SOC-gated checks',
        'Create safe validation policy',
        'Safe validation policies'
      ];
      for (const snippet of required) {
        if (!bodyText.toLowerCase().includes(snippet.toLowerCase())) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }

      async function metricValue(label) {
        const card = page.locator('.metric-card').filter({ hasText: label });
        if (await card.count() === 0) return '';
        return (await card.locator('strong').first().innerText()).trim();
      }

      const activePoliciesMetric = await metricValue('Active policies');
      const safeChecksMetric = await metricValue('Safe checks');
      const socGatedMetric = await metricValue('SOC-gated checks');

      if (activePoliciesMetric !== String(policyItems.length)) {
        fail('l1', `${viewport.name}: active policies metric mismatch UI=${activePoliciesMetric} API=${policyItems.length}`);
      }
      if (safeChecksMetric !== String(safeChecks.length)) {
        fail('l1', `${viewport.name}: safe checks metric mismatch UI=${safeChecksMetric} API=${safeChecks.length}`);
      }
      if (socGatedMetric !== String(socGatedChecks.length)) {
        fail('l1', `${viewport.name}: SOC-gated metric mismatch UI=${socGatedMetric} API=${socGatedChecks.length}`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      const benignConsole = (detail) => /favicon/i.test(detail) || /429/.test(detail);
      if (consoleErrors.filter((e) => !benignConsole(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      if (viewport.name === 'desktop') {
        const checkMeta = fixture.safeChecks.find((check) => check.check_id === safeCheckId);
        const checkLabel = checkMeta?.name ?? safeCheckId;

        await page.waitForSelector(`select[name="target_group_id"] option[value="${targetGroupId}"]`, { state: 'attached', timeout: 20000 });
        await page.locator('select[name="target_group_id"]').selectOption(targetGroupId);
        await page.locator('select[name="check_id"]').selectOption(safeCheckId);
        await page.locator('select[name="cadence"]').selectOption('weekly');
        await page.locator('select[name="expected_verdict"]').selectOption('pass');

        const createResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/test-policies') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Create policy' }).click();
        const createdRes = await createResponse;
        if (!createdRes.ok()) {
          fail('l2', `browser create failed (${createdRes.status()})`);
        } else {
          const createdJson = await createdRes.json();
          const createdId = createdJson?.id ?? '';
          note('l2', `browser create ok (${createdId})`);
          await page.waitForTimeout(1200);
          const afterCreate = await page.locator('body').innerText();
          if (createdId && !afterCreate.includes(createdJson.check?.name ?? checkLabel)) {
            fail('l2', 'created policy row not visible after create');
          }

          if (createdId) {
            const policyRow = page.locator('tr', { hasText: createdJson.check?.name ?? checkLabel }).last();

            const patchResponse = page.waitForResponse(
              (res) => res.url().includes(`/v1/test-policies/${createdId}`) && res.request().method() === 'PATCH',
              { timeout: 20000 }
            );
            await policyRow.getByRole('button', { name: 'Pause' }).click();
            const pauseRes = await patchResponse;
            if (!pauseRes.ok()) fail('l2', `browser pause failed (${pauseRes.status()})`);
            else note('l2', 'browser pause ok');

            await page.waitForTimeout(800);
            const resumeResponse = page.waitForResponse(
              (res) => res.url().includes(`/v1/test-policies/${createdId}`) && res.request().method() === 'PATCH',
              { timeout: 20000 }
            );
            await policyRow.getByRole('button', { name: 'Resume' }).click();
            const resumeRes = await resumeResponse;
            if (!resumeRes.ok()) fail('l2', `browser resume failed (${resumeRes.status()})`);
            else note('l2', 'browser resume ok');

            const weeklyResponse = page.waitForResponse(
              (res) => res.url().includes(`/v1/test-policies/${createdId}`) && res.request().method() === 'PATCH',
              { timeout: 20000 }
            );
            await policyRow.getByRole('button', { name: 'Weekly' }).click();
            const weeklyRes = await weeklyResponse;
            if (!weeklyRes.ok()) fail('l2', `browser weekly cadence failed (${weeklyRes.status()})`);
            else note('l2', 'browser weekly cadence ok');

            const archiveResponse = page.waitForResponse(
              (res) => res.url().includes(`/v1/test-policies/${createdId}`) && res.request().method() === 'DELETE',
              { timeout: 20000 }
            );
            await policyRow.getByRole('button', { name: 'Archive' }).click();
            const archiveRes = await archiveResponse;
            if (!archiveRes.ok()) fail('l2', `browser archive failed (${archiveRes.status()})`);
            else note('l2', 'browser archive ok');
          }
        }
      }

      note('l3', `${viewport.name}: test-policies render ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  const fixture = await runL1();
  await runL2(fixture);
  await runL3(fixture);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-09');
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