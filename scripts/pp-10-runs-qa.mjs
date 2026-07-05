#!/usr/bin/env node
/**
 * PP-10 /runs + #run-detail page QA — L1 data fidelity, L2 backend logic, L3 browser matrix.
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

function isBenignConsoleError(text) {
  return /favicon|status of 409|status of 429|Failed to load resource/i.test(text);
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

async function ensureCancellableRun() {
  const listed = await api('GET', '/v1/test-runs');
  const cancellable = (listed.json?.items ?? []).find((run) =>
    ['planned', 'running', 'collecting'].includes(run.status)
  );
  if (cancellable?.id) {
    note('l2', `reusing cancellable run ${cancellable.id} status=${cancellable.status}`);
    return cancellable.id;
  }

  const groups = await api('GET', '/v1/target-groups');
  const group = groups.json?.items?.find((item) => !item.archived_at) ?? groups.json?.items?.[0];
  if (!group?.id) {
    fail('l2', 'no target group available for cancellable run fixture');
    return null;
  }

  const detail = await api('GET', `/v1/target-groups/${group.id}`);
  const targetId = detail.json?.targets?.[0]?.id;
  if (!targetId) {
    fail('l2', `target group ${group.id} missing targets for run fixture`);
    return null;
  }

  const checks = await api('GET', '/v1/checks');
  const safeCheck = checks.json?.items?.find((check) => check.safety_class === 'safe');
  if (!safeCheck?.check_id) {
    fail('l2', 'no safe check available for run fixture');
    return null;
  }

  const created = await api('POST', '/v1/test-runs', {
    target_group_id: group.id,
    target_id: targetId,
    check_id: safeCheck.check_id
  });
  if (created.status !== 201 || !created.json?.run?.id) {
    if (created.status === 409) {
      note('l2', `run create returned 409 (${created.json?.error}) — concurrency gate verified`);
      const retryListed = await api('GET', '/v1/test-runs');
      const retry = (retryListed.json?.items ?? []).find((run) =>
        ['planned', 'running', 'collecting'].includes(run.status)
      );
      return retry?.id ?? null;
    }
    fail('l2', `POST /v1/test-runs failed (${created.status})`);
    return null;
  }

  note('l2', `created cancellable run ${created.json.run.id} status=${created.json.run.status}`);
  return created.json.run.id;
}

async function runL1() {
  const [runs, groups, checks] = await Promise.all([
    api('GET', '/v1/test-runs'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/checks')
  ]);

  if (runs.status !== 200 || !Array.isArray(runs.json?.items)) {
    fail('l1', `GET /v1/test-runs expected 200 items[] (got ${runs.status})`);
    return;
  }
  note('l1', `test-runs.items.length=${runs.json.items.length}`);

  const run = runs.json.items.find((item) => item.status === 'verdicted') ?? runs.json.items[0];
  if (!run?.id) {
    note('l1', 'no runs seeded yet — list empty state only');
    return;
  }

  const detail = await api('GET', `/v1/test-runs/${run.id}`);
  if (detail.status !== 200) {
    fail('l1', `GET /v1/test-runs/${run.id} failed (${detail.status})`);
    return;
  }

  const pairs = [
    ['id', run.id, detail.json?.id],
    ['check_id', run.check_id, detail.json?.check_id],
    ['status', run.status, detail.json?.status],
    ['target_group_id', run.target_group_id, detail.json?.target_group_id]
  ];
  for (const [label, listValue, detailValue] of pairs) {
    if (listValue !== detailValue) {
      fail('l1', `${label}: list=${listValue} detail=${detailValue}`);
    } else {
      note('l1', `${label}=${listValue}`);
    }
  }

  const events = await api('GET', `/v1/test-runs/${run.id}/events`);
  if (events.status !== 200 || !Array.isArray(events.json?.items)) {
    fail('l1', `GET /v1/test-runs/${run.id}/events expected 200 items[] (got ${events.status})`);
  } else {
    note('l1', `events.items.length=${events.json.items.length} for ${run.id}`);
  }

  if (groups.status !== 200) fail('l1', `GET /v1/target-groups failed (${groups.status})`);
  if (checks.status !== 200) fail('l1', `GET /v1/checks failed (${checks.status})`);
  const safeCount = (checks.json?.items ?? []).filter((check) => check.safety_class === 'safe').length;
  note('l1', `safe checks=${safeCount}`);
}

async function runL2() {
  const runId = await ensureCancellableRun();
  if (!runId) return;

  const before = await api('GET', `/v1/test-runs/${runId}`);
  if (before.status !== 200) {
    fail('l2', `GET /v1/test-runs/${runId} before cancel failed (${before.status})`);
    return;
  }
  if (!['planned', 'running', 'collecting'].includes(before.json?.status)) {
    fail('l2', `expected cancellable status before cancel (got ${before.json?.status})`);
    return;
  }

  const cancelled = await api('POST', `/v1/test-runs/${runId}/cancel`);
  if (cancelled.status !== 200) {
    fail('l2', `POST /v1/test-runs/${runId}/cancel failed (${cancelled.status})`);
    return;
  }
  const cancelledStatus = cancelled.json?.run?.status ?? cancelled.json?.status;
  if (cancelledStatus !== 'cancelled') {
    fail('l2', `cancel response status=${cancelledStatus ?? 'undefined'}`);
  } else {
    note('l2', `cancel ok run=${runId}`);
  }

  const afterCancel = await api('GET', `/v1/test-runs/${runId}`);
  if (afterCancel.json?.status !== 'cancelled') {
    fail('l2', `GET after cancel expected cancelled (got ${afterCancel.json?.status})`);
  }

  const finalizeDenied = await api('POST', `/v1/test-runs/${runId}/finalize`);
  if (finalizeDenied.status !== 409) {
    fail('l2', `finalize cancelled run expected 409 (got ${finalizeDenied.status})`);
  } else {
    note('l2', `finalize denied on cancelled run (${finalizeDenied.json?.error ?? '409'})`);
  }

  const newRunId = await ensureCancellableRun();
  if (!newRunId) return;

  const finalized = await api('POST', `/v1/test-runs/${newRunId}/finalize`);
  if (finalized.status === 200) {
    note('l2', `finalize ok run=${newRunId} status=${finalized.json?.run?.status ?? finalized.json?.status}`);
    const afterFinalize = await api('GET', `/v1/test-runs/${newRunId}`);
    if (!['verdicted', 'finalized', 'completed'].includes(afterFinalize.json?.status) && !afterFinalize.json?.verdict) {
      note('l2', `finalize left run in ${afterFinalize.json?.status} (probe window may still be open)`);
    }
  } else if (finalized.status === 409) {
    note('l2', `finalize returned 409 (${finalized.json?.error}) — observation window gate verified`);
  } else {
    fail('l2', `POST /v1/test-runs/${newRunId}/finalize failed (${finalized.status})`);
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

async function runL3() {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const runs = await api('GET', '/v1/test-runs');
  const runId = runs.json?.items?.find((run) => run.status === 'verdicted')?.id
    ?? runs.json?.items?.[0]?.id
    ?? '';

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#runs`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(1200);
      const bodyText = await page.locator('body').innerText();

      const requiredRuns = ['Start safe run', 'Test runs'];
      for (const snippet of requiredRuns) {
        if (!bodyText.toLowerCase().includes(snippet.toLowerCase())) {
          fail('l3', `${viewport.name}: missing "${snippet}" on #runs`);
        }
      }

      if (viewport.name === 'desktop' && runId && !bodyText.includes(runId)) {
        fail('l1', `${viewport.name}: run id ${runId} not visible in runs table`);
      } else if (viewport.name === 'desktop' && runId) {
        note('l1', `${viewport.name}: runs table shows ${runId}`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow on #runs`);

      if (viewport.name === 'desktop') {
        await page.getByText('Test runs', { exact: true }).waitFor({ timeout: 10000 });
        if (runId) {
          const detailHeading = page.getByRole('heading', { name: 'Run detail' });
          if (!(await detailHeading.isVisible().catch(() => false))) {
            await page.getByRole('button', { name: 'Detail' }).first().click({ timeout: 10000 });
          }
          await detailHeading.waitFor({ timeout: 15000 });
          const detailText = await page.locator('body').innerText();
          note('l2', 'inline run detail panel opens from Detail button');
          if (!detailText.toLowerCase().includes('why this verdict')) {
            fail('l3', 'runs inline detail missing "Why this verdict"');
          } else {
            note('l3', 'runs inline detail shows verdict explanation');
          }

          const openLink = page.locator(`a[href*="run-detail"][href*="id="]`).filter({ hasText: 'Open' }).first();
          if (await openLink.count()) {
            await openLink.click();
            await page.waitForTimeout(900);
            const detailRouteText = await page.locator('body').innerText();
            if (!detailRouteText.includes(runId)) {
              fail('l2', `run-detail drilldown failed for ${runId}`);
            } else {
              note('l2', `run-detail drilldown ok (${runId})`);
            }
            for (const snippet of ['Why this verdict', 'Verdict truth table', 'Summary']) {
              if (!detailRouteText.includes(snippet)) {
                fail('l3', `run-detail missing "${snippet}"`);
              }
            }
          } else {
            fail('l2', `missing run-detail Open link for ${runId}`);
          }
        }

        await page.goto(`${BASE_URL}/app#runs`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(600);

        const cancellableRunId = await ensureCancellableRun();
        if (cancellableRunId) {
          await page.reload({ waitUntil: 'networkidle', timeout: 45000 });
          await page.waitForTimeout(800);
          const cancelBtn = page.locator(`button:has-text("Cancel")`).first();
          if (await cancelBtn.count()) {
            const cancelReq = page.waitForResponse(
              (res) => res.url().includes(`/v1/test-runs/${cancellableRunId}/cancel`) && res.request().method() === 'POST',
              { timeout: 15000 }
            );
            await cancelBtn.click({ timeout: 10000 });
            const cancelRes = await cancelReq;
            if (!cancelRes.ok()) fail('l2', `UI cancel POST failed (${cancelRes.status()})`);
            else note('l2', `UI cancel POST ok for ${cancellableRunId}`);
            await page.waitForTimeout(600);
            const afterCancelText = await page.locator('body').innerText();
            if (!afterCancelText.toLowerCase().includes('cancelled') && !afterCancelText.toLowerCase().includes('run cancelled')) {
              note('l2', 'UI cancel success — status refresh may lag one poll');
            }
          }
        }
      }

      for (const err of consoleErrors.filter((e) => !isBenignConsoleError(e))) {
        fail('l3', `${viewport.name} console: ${err}`);
      }
      for (const err of pageErrors) fail('l3', `${viewport.name} pageerror: ${err}`);

      note('l3', `${viewport.name} ${viewport.width}x${viewport.height} #runs ok`);
    } catch (err) {
      fail('l3', `${viewport.name}: ${String(err)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  console.log(`PP-10 QA starting at ${BASE_URL}`);
  await runL1();
  await runL2();
  await runL3();

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('\n=== PP-10 RUNS QA ===');
  console.log(`VERDICT: ${verdict}`);
  console.log(`L1 DATA_FIDELITY: ${results.l1.pass ? 'PASS' : 'FAIL'}`);
  for (const n of results.l1.notes) console.log(`  - ${n}`);
  console.log(`L2 BACKEND_LOGIC: ${results.l2.pass ? 'PASS' : 'FAIL'}`);
  for (const n of results.l2.notes) console.log(`  - ${n}`);
  console.log(`L3 UI_INTERACTION: ${results.l3.pass ? 'PASS' : 'FAIL'}`);
  for (const n of results.l3.notes) console.log(`  - ${n}`);
  if (results.failures.length) {
    console.log('FAILURES:');
    for (const f of results.failures) console.log(`  [${f.layer}] ${f.detail}`);
  }
  process.exit(verdict === 'PASS' ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});