#!/usr/bin/env node
/**
 * PP-17 /integrations page QA — L1 data fidelity, L2 connector/secret actions, L3 browser matrix.
 */
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

function bodyIncludesSnippet(bodyText, snippet) {
  return bodyText.toLowerCase().includes(snippet.toLowerCase());
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
  return { status: res.status, json, text };
}

async function fetchFixture() {
  const [features, connectors, secrets] = await Promise.all([
    api('GET', '/v1/tenant/deployment-features'),
    api('GET', '/v1/connectors'),
    api('GET', '/v1/secrets')
  ]);
  return {
    features,
    connectors,
    secrets,
    connectorItems: connectors.json?.items ?? [],
    secretItems: secrets.json?.items ?? [],
    connectorsEnabled: features.json?.connectors === true
  };
}

async function runL1() {
  const fixture = await fetchFixture();

  if (fixture.features.status !== 200) fail('l1', `deployment-features failed (${fixture.features.status})`);
  if (!fixture.connectorsEnabled) fail('l1', 'connectors feature flag disabled — restart server with ASTRANULL_CONNECTORS_ENABLED=1');
  if (fixture.connectors.status !== 200) fail('l1', `GET /v1/connectors failed (${fixture.connectors.status})`);
  if (fixture.secrets.status !== 200) fail('l1', `GET /v1/secrets failed (${fixture.secrets.status})`);

  note('l1', `connectors=${fixture.connectorItems.length}`);
  note('l1', `secrets=${fixture.secretItems.length}`);
  note('l1', `feature_connectors=${fixture.connectorsEnabled}`);

  for (const connector of fixture.connectorItems) {
    if (!connector.id) fail('l1', 'connector missing id');
    if (!connector.provider) fail('l1', `connector ${connector.id} missing provider`);
    if (!connector.status) fail('l1', `connector ${connector.id} missing status`);
  }

  return fixture;
}

async function runL2(fixture) {
  const created = await api('POST', '/v1/connectors', {
    provider: 'cloudflare',
    name: `pp17-qa-${Date.now()}`,
    secret_id: 'sec_pointer_1',
    status: 'active',
    config: { read_only: true, default_snapshot_kind: 'waf_policy' }
  });
  if (created.status !== 201 || !created.json?.connector?.id) {
    fail('l2', `POST /v1/connectors failed (${created.status}) ${created.json?.error ?? ''}`);
    return null;
  }
  const connectorId = created.json.connector.id;
  note('l2', `created connector ${connectorId}`);

  const validate = await api('POST', `/v1/connectors/${connectorId}/validate`);
  if (validate.status !== 200 || validate.json?.status !== 'active') {
    fail('l2', `validate failed (${validate.status}) status=${validate.json?.status}`);
  } else {
    note('l2', 'validate ok');
  }

  const poll = await api('POST', `/v1/connectors/${connectorId}/poll`, {
    manual_only: true,
    snapshots: [{
      snapshot_kind: 'cdn_property',
      resource_ref_hash: 'res_pp17',
      display_ref: 'zone-pp17',
      config_hash: 'cfg_pp17',
      summary: { policy_mode: 'monitor', rule_count: 2, hostnames: ['pp17.example.com'] }
    }]
  });
  if (poll.status !== 202 || !Array.isArray(poll.json?.snapshots) || poll.json.snapshots.length < 1) {
    fail('l2', `manual poll failed (${poll.status}) ${poll.json?.message ?? poll.json?.error ?? ''}`);
  } else {
    note('l2', `manual poll snapshots=${poll.json.snapshots.length}`);
  }

  const snapshots = await api('GET', `/v1/connectors/${connectorId}/snapshots`);
  if (snapshots.status !== 200 || !(snapshots.json?.items ?? []).length) {
    fail('l2', `GET snapshots failed (${snapshots.status})`);
  } else {
    note('l2', `snapshots listed=${snapshots.json.items.length}`);
  }

  const invalidKind = await api('POST', `/v1/connectors/${connectorId}/poll`, {
    manual_only: true,
    snapshots: [{
      snapshot_kind: 'waf_rule',
      resource_ref_hash: 'bad',
      display_ref: 'bad',
      config_hash: 'bad',
      summary: { policy_mode: 'monitor', rule_count: 0 }
    }]
  });
  if (invalidKind.status !== 400) {
    fail('l2', `invalid snapshot_kind should return 400 got ${invalidKind.status}`);
  } else {
    note('l2', 'invalid snapshot_kind boundary ok');
  }

  const disable = await api('POST', `/v1/connectors/${connectorId}/disable`, {
    reason: 'PP-17 QA disable'
  });
  if (disable.status !== 200 || disable.json?.connector?.status !== 'disabled') {
    fail('l2', `disable failed (${disable.status})`);
  } else {
    note('l2', 'disable ok');
  }

  const listed = await api('GET', '/v1/connectors');
  const row = (listed.json?.items ?? []).find((item) => item.id === connectorId);
  if (!row || row.status !== 'disabled') {
    fail('l2', `list missing disabled connector ${connectorId}`);
  } else {
    note('l2', 'list reflects disabled status');
  }

  return { connectorId, connectorName: created.json.connector.name };
}

async function ensurePlaywright() {
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

async function runL3(fixture, created) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  for (const viewport of VIEWPORTS) {
    const fresh = await fetchFixture();
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#integrations`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(1200);
      let bodyText = await page.locator('body').innerText();

      const required = [
        'Integrations',
        'Create read-only connector',
        'Configured connectors',
        'Connector snapshots',
        'Secret refs'
      ];
      for (const snippet of required) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }

      if (!bodyText.includes(String(fresh.connectorItems.length))) {
        fail('l1', `${viewport.name}: connector count mismatch (expected ${fresh.connectorItems.length})`);
      }
      if (!bodyText.includes(String(fresh.secretItems.length))) {
        fail('l1', `${viewport.name}: secret refs count mismatch (expected ${fresh.secretItems.length})`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (viewport.name === 'desktop' && created) {
        const row = page.locator('tr', { hasText: created.connectorName }).first();
        if (await row.count()) {
          const snapshotsResponse = page.waitForResponse(
            (res) => res.url().includes('/snapshots') && res.request().method() === 'GET',
            { timeout: 20000 }
          );
          await row.getByRole('button', { name: 'Snapshots' }).click();
          const snapRes = await snapshotsResponse;
          if (!snapRes.ok()) fail('l2', `browser snapshots failed (${snapRes.status()})`);
          else note('l2', 'browser snapshots ok');
        } else {
          fail('l3', 'desktop: created connector row not visible in table');
        }

        await page.locator('input[name="name"]').fill(`pp17-browser-${Date.now()}`);
        const createResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/connectors') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Create connector' }).click();
        const createRes = await createResponse;
        if (createRes.status() !== 201) fail('l2', `browser create connector failed (${createRes.status()})`);
        else note('l2', 'browser create connector ok');

        await page.waitForTimeout(800);
        const activeRow = page.locator('tr', { hasText: 'pp17-browser' }).first();
        if (await activeRow.count()) {
          const validateResponse = page.waitForResponse(
            (res) => res.url().includes('/validate') && res.request().method() === 'POST',
            { timeout: 20000 }
          );
          await activeRow.getByRole('button', { name: 'Validate' }).click();
          const valRes = await validateResponse;
          if (!valRes.ok()) fail('l2', `browser validate failed (${valRes.status()})`);
          else note('l2', 'browser validate ok');

          const pollResponse = page.waitForResponse(
            (res) => res.url().includes('/poll') && res.request().method() === 'POST',
            { timeout: 20000 }
          );
          await activeRow.getByRole('button', { name: 'Poll' }).click();
          const pollRes = await pollResponse;
          if (pollRes.status() !== 202) fail('l2', `browser poll failed (${pollRes.status()})`);
          else note('l2', 'browser poll ok');
        } else {
          fail('l3', 'desktop: browser-created connector row not visible');
        }
      }

      if (consoleErrors.filter((e) => !/favicon/i.test(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      note('l3', `${viewport.name}: integrations ok`);
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
  const created = await runL2(fixture);
  if (created) await runL3(fixture, created);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-17');
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