#!/usr/bin/env node
/**
 * PP-14 /high-scale page QA — L1 data fidelity, L2 backend logic, L3 browser matrix.
 * CRITICAL: customer page must NOT call /internal/soc/* execution routes.
 */
import { createHash } from 'node:crypto';
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

function defaultWindow() {
  const windowStart = new Date(Date.now() + 86400000).toISOString();
  const windowEnd = new Date(Date.now() + 172800000).toISOString();
  return { windowStart, windowEnd };
}

function validRequestPayload(groupId, suffix) {
  const { windowStart, windowEnd } = defaultWindow();
  return {
    target_group_id: groupId,
    objective: `PP14 QA request ${suffix}`,
    environment: 'staging',
    business_criticality: 'high',
    requested_scenario_families: ['volumetric_metadata'],
    requested_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
    stop_criteria: { abort_on_customer_signal: true, max_error_rate_pct: 5 },
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    requested_window: {
      window_start: windowStart,
      window_end: windowEnd,
      timezone: 'UTC'
    },
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    provider_context: { provider_name: 'Cloudflare', requires_provider_approval: true },
    scope_confirmation: true
  };
}

function artifactProofBody(type, groupId) {
  const { windowStart, windowEnd } = defaultWindow();
  const digest = createHash('sha256').update(`pp14-artifact:${type}`).digest('hex');
  return {
    type,
    filename: `${type}.metadata.json`,
    content_sha256: digest,
    reference_uri: `metadata://high-scale/${type}/pp14`,
    approval_reference: 'REF-PP14',
    approver: 'Customer Approver',
    valid_window: { valid_from: windowStart, valid_to: windowEnd },
    approved_targets: [groupId],
    approved_scenario_families: ['volumetric_metadata'],
    max_rate: '500_rps_metadata',
    max_duration_minutes: 45,
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    retention_policy: { retain_days: 90, classification: 'governance' }
  };
}

async function runL1() {
  const [hs, groups, state] = await Promise.all([
    api('GET', '/v1/high-scale-requests'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/state')
  ]);

  if (hs.status !== 200 || !Array.isArray(hs.json?.items)) {
    fail('l1', `GET /v1/high-scale-requests expected 200 items[] (got ${hs.status})`);
    return;
  }

  const count = hs.json.items.length;
  note('l1', `high-scale-requests.items.length=${count}`);

  if (state.status === 200 && state.json?.high_scale_requests !== count) {
    fail('l1', `state.high_scale_requests=${state.json?.high_scale_requests} list=${count}`);
  } else if (state.status === 200) {
    note('l1', `state.high_scale_requests=${state.json.high_scale_requests}`);
  }

  if (groups.status !== 200 || !Array.isArray(groups.json?.items) || groups.json.items.length === 0) {
    fail('l1', 'GET /v1/target-groups missing items for intake form');
    return;
  }
  note('l1', `targetGroups.items.length=${groups.json.items.length}`);

  const selected = hs.json.items[0];
  if (selected) {
    const packOverall = selected.authorization_pack_status?.overall ?? 'missing';
    const artifactCount = Array.isArray(selected.artifacts) ? selected.artifacts.length : 0;
    note('l1', `selected request id=${selected.id} state=${selected.state} pack=${packOverall} artifacts=${artifactCount}`);
    if (selected.objective && !String(selected.objective).includes('PP14')) {
      note('l1', `seeded request objective=${selected.objective}`);
    }
  }
}

async function runL2() {
  const groups = await api('GET', '/v1/target-groups');
  const groupId = groups.json?.items?.[0]?.id;
  if (!groupId) {
    fail('l2', 'no target group available for high-scale create');
    return;
  }

  const suffix = Date.now();
  const createRes = await api('POST', '/v1/high-scale-requests', validRequestPayload(groupId, suffix));
  if (createRes.status !== 201 || !createRes.json?.id) {
    fail('l2', `POST /v1/high-scale-requests failed (${createRes.status} ${createRes.json?.error ?? ''})`);
    return;
  }
  const requestId = createRes.json.id;
  note('l2', `created request ${requestId} state=${createRes.json.state}`);

  const listAfterCreate = await api('GET', '/v1/high-scale-requests');
  const createdRow = listAfterCreate.json?.items?.find((item) => item.id === requestId);
  if (!createdRow) {
    fail('l2', `GET list missing created request ${requestId}`);
  } else if (createdRow.state !== 'submitted') {
    fail('l2', `created request state=${createdRow.state} expected submitted`);
  } else {
    note('l2', 'list includes created submitted request');
  }

  const artRes = await api(
    'POST',
    `/v1/high-scale-requests/${requestId}/artifacts`,
    artifactProofBody('test_plan', groupId)
  );
  if (artRes.status !== 201 || !artRes.json?.id) {
    fail('l2', `POST artifact failed (${artRes.status} ${artRes.json?.error ?? ''})`);
    return;
  }
  note('l2', `uploaded test_plan artifact id=${artRes.json.id} status=${artRes.json.status}`);

  const listAfterArtifact = await api('GET', '/v1/high-scale-requests');
  const artifactRow = listAfterArtifact.json?.items?.find((item) => item.id === requestId);
  const artifacts = Array.isArray(artifactRow?.artifacts) ? artifactRow.artifacts : [];
  if (!artifacts.some((item) => item.type === 'test_plan')) {
    fail('l2', 'list response missing uploaded test_plan artifact');
  } else {
    note('l2', `list artifacts.length=${artifacts.length}`);
  }

  const socProbe = await api('POST', `/internal/soc/high-scale/${requestId}/approve`, {}, {
    ...HEADERS,
    'x-role': 'soc_analyst'
  });
  if (socProbe.status === 200 || socProbe.status === 201) {
    note('l2', 'SOC approve reachable with soc role (not invoked from customer page)');
  } else if (socProbe.status === 403) {
    note('l2', 'SOC approve denied without soc role (RBAC ok)');
  } else {
    note('l2', `SOC approve probe status=${socProbe.status} (customer page must not call this)`);
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

  const hsBefore = await api('GET', '/v1/high-scale-requests');
  if (hsBefore.status === 429 || hsBefore.json?.error === 'rate_limited') {
    fail('l3', 'API rate_limited before browser matrix — restart server with ASTRANULL_RATE_LIMIT_DISABLED=1');
    await browser.close();
    return;
  }

  const requestCount = hsBefore.json?.items?.length ?? 0;
  const selected = hsBefore.json?.items?.[0];
  const artifactCount = Array.isArray(selected?.artifacts) ? selected.artifacts.length : 0;
  const packOverall = selected?.authorization_pack_status?.overall ?? 'missing';

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    const socCalls = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));
    page.on('request', (req) => {
      const url = req.url();
      if (url.includes('/internal/soc/high-scale/')) socCalls.push(`${req.method()} ${url}`);
    });

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#high-scale`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(2000);
      const bodyText = await page.locator('body').innerText();

      const required = [
        'SOC-gated validation',
        'Request governed validation',
        'Authorization pack uploads',
        'High-scale requests',
        'SOC handoff',
        'Submit high-scale request',
        'does not call `/internal/soc/*`'
      ];
      for (const snippet of required) {
        if (!bodyText.toLowerCase().includes(snippet.toLowerCase())) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }
      if (requestCount > 0 && !bodyText.includes('Upload metadata')) {
        fail('l3', `${viewport.name}: missing "Upload metadata" with ${requestCount} request(s) in API`);
      }

      if (requestCount > 0) {
        if (!bodyText.includes(String(requestCount))) {
          fail('l1', `${viewport.name}: Requests metric missing count ${requestCount}`);
        } else {
          note('l1', `${viewport.name}: Requests metric shows ${requestCount}`);
        }
        if (selected?.objective && viewport.name === 'desktop') {
          const objectiveSnippet = String(selected.objective).slice(0, 24);
          if (!bodyText.includes(objectiveSnippet)) {
            fail('l1', `${viewport.name}: table missing objective snippet "${objectiveSnippet}"`);
          } else {
            note('l1', `${viewport.name}: table shows objective snippet "${objectiveSnippet}"`);
          }
        } else if (selected?.objective && viewport.name !== 'desktop') {
          const optionText = await page.locator('select option').allTextContents().catch(() => []);
          const objectiveSnippet = String(selected.objective).slice(0, 24);
          if (!optionText.some((text) => text.includes(objectiveSnippet))) {
            note('l1', `${viewport.name}: request selector may abbreviate objectives on narrow viewports`);
          } else {
            note('l1', `${viewport.name}: request selector shows objective snippet "${objectiveSnippet}"`);
          }
        }
        if (packOverall !== 'None' && !bodyText.toLowerCase().includes(String(packOverall).toLowerCase())) {
          note('l1', `${viewport.name}: pack overall=${packOverall} (may be abbreviated in UI)`);
        }
        if (artifactCount > 0 && !bodyText.includes('test_plan') && !bodyText.includes('Test Plan')) {
          note('l1', `${viewport.name}: artifact table may abbreviate types`);
        }
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (socCalls.length) {
        fail('l2', `${viewport.name}: customer page called SOC routes: ${socCalls.join('; ')}`);
      } else {
        note('l2', `${viewport.name}: no /internal/soc/high-scale/* network calls`);
      }

      if (viewport.name === 'desktop') {
        const objective = `PP14 UI request ${Date.now()}`;
        await page.locator('textarea[name="objective"]').fill(objective);
        const createReq = page.waitForResponse(
          (res) => res.url().includes('/v1/high-scale-requests') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Submit high-scale request' }).click({ timeout: 10000 });
        const createRes = await createReq;
        const createBody = createRes.request().postDataJSON?.();
        if (!createRes.ok()) {
          fail('l2', `UI create POST failed (${createRes.status()})`);
        } else if (!createBody?.scope_confirmation) {
          fail('l2', 'UI create missing scope_confirmation=true');
        } else if (!Array.isArray(createBody?.requested_scenario_families)) {
          fail('l2', 'UI create missing requested_scenario_families');
        } else {
          note('l2', `UI create POST 201 objective="${createBody.objective}"`);
        }
        await page.waitForTimeout(1500);
        const afterCreateText = await page.locator('body').innerText();
        if (!afterCreateText.includes(objective)) {
          fail('l1', `UI list missing created objective "${objective}"`);
        }

        const uploadBtn = page.getByRole('button', { name: 'Upload metadata' }).first();
        const filenameInput = page.locator('input[placeholder*=".metadata"]').first();
        await filenameInput.fill(`pp14-ui-test-plan-${Date.now()}.metadata.json`);
        const uploadReq = page.waitForResponse(
          (res) => res.url().includes('/artifacts') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await uploadBtn.click({ timeout: 10000 });
        const uploadRes = await uploadReq;
        const uploadBody = uploadRes.request().postDataJSON?.();
        if (!uploadRes.ok()) {
          fail('l2', `UI artifact POST failed (${uploadRes.status()})`);
        } else if (!uploadBody?.type || !uploadBody?.content_sha256) {
          fail('l2', 'UI artifact POST missing type/content_sha256');
        } else {
          note('l2', `UI artifact POST 201 type=${uploadBody.type}`);
        }

        const socLink = page.locator('a[href="#soc"]').first();
        if (await socLink.count()) {
          await socLink.click();
          await page.waitForTimeout(800);
          const socText = await page.locator('body').innerText();
          if (!socText.toLowerCase().includes('soc')) {
            fail('l2', 'SOC handoff link did not navigate to SOC surface');
          } else {
            note('l2', 'SOC handoff link navigates to #soc');
          }
        }
      }

      for (const err of consoleErrors.filter((e) => !isBenignConsoleError(e))) {
        fail('l3', `${viewport.name} console: ${err}`);
      }
      for (const err of pageErrors) fail('l3', `${viewport.name} pageerror: ${err}`);

      note('l3', `${viewport.name} ${viewport.width}x${viewport.height} render ok`);
    } catch (err) {
      fail('l3', `${viewport.name}: ${String(err)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  console.log(`PP-14 QA starting at ${BASE_URL}`);
  await runL1();
  await runL2();
  const hsAfterL2 = await api('GET', '/v1/high-scale-requests');
  if (hsAfterL2.status === 200 && (hsAfterL2.json?.items?.length ?? 0) > 0) {
    note('l1', `post-L2 high-scale-requests.items.length=${hsAfterL2.json.items.length}`);
  } else if (hsAfterL2.json?.error === 'rate_limited') {
    fail('l1', 'rate_limited after L2 mutations');
  }
  await runL3();

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('\n=== PP-14 HIGH-SCALE QA ===');
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