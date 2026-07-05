#!/usr/bin/env node
/**
 * PP-16 /reports + #report-detail page QA — L1 data fidelity, L2 create/export/custody, L3 browser matrix.
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
  return { status: res.status, json, text, contentType: res.headers.get('content-type') ?? '' };
}

async function fetchFixture() {
  const [reports, audit] = await Promise.all([
    api('GET', '/v1/reports'),
    api('GET', '/v1/audit-log')
  ]);
  const reportItems = reports.json?.items ?? [];
  const reportExports = (audit.json?.items ?? []).filter((entry) => entry.action === 'report.exported').length;
  const latestReport = reportItems[0] ?? null;
  return { reports, audit, reportItems, reportExports, latestReport };
}

async function runL1() {
  const fixture = await fetchFixture();
  const { reports, audit, reportItems, reportExports, latestReport } = fixture;

  if (reports.status !== 200) fail('l1', `GET /v1/reports failed (${reports.status})`);
  if (audit.status !== 200) fail('l1', `GET /v1/audit-log failed (${audit.status})`);

  note('l1', `reports=${reportItems.length}`);
  note('l1', `report_exports_audit=${reportExports}`);
  note('l1', `latest_kind=${latestReport?.kind ?? 'none'}`);

  for (const report of reportItems) {
    if (!report.id) fail('l1', 'report missing id');
    if (!report.kind) fail('l1', `report ${report.id} missing kind`);
    if (typeof report.summary?.readiness_score !== 'number') {
      fail('l1', `report ${report.id} missing summary.readiness_score`);
    }
    if (typeof report.summary?.open_findings !== 'number') {
      fail('l1', `report ${report.id} missing summary.open_findings`);
    }
  }

  return { reportItems, reportExports, latestReport };
}

async function runL2(fixture) {
  const created = await api('POST', '/v1/reports', {
    title: `PP-16 QA ${Date.now()}`,
    kind: 'audit'
  });
  if (created.status !== 201 || !created.json?.id) {
    fail('l2', `POST /v1/reports failed (${created.status})`);
    return null;
  }
  const reportId = created.json.id;
  note('l2', `created report ${reportId}`);

  const detail = await api('GET', `/v1/reports/${reportId}`);
  if (detail.status !== 200) {
    fail('l2', `GET /v1/reports/:id failed (${detail.status})`);
  } else if (detail.json?.kind !== 'audit') {
    fail('l2', `detail kind mismatch expected audit got ${detail.json?.kind}`);
  } else {
    note('l2', 'detail fetch ok');
  }

  const jsonExport = await api('GET', `/v1/reports/${reportId}/export?format=json`);
  if (jsonExport.status !== 200 || !jsonExport.json?.custody?.content_sha256) {
    fail('l2', `JSON export failed (${jsonExport.status})`);
  } else {
    note('l2', `json export sha=${jsonExport.json.custody.content_sha256.slice(0, 12)}…`);
  }

  const verify = await api('POST', '/v1/custody/verify', {
    payload: jsonExport.json?.payload,
    custody: jsonExport.json?.custody
  });
  if (verify.status !== 200 || verify.json?.ok !== true) {
    fail('l2', `custody verify failed (${verify.status}) ok=${verify.json?.ok}`);
  } else {
    note('l2', 'custody verify ok');
  }

  const mdExport = await api('GET', `/v1/reports/${reportId}/export?format=markdown`);
  if (mdExport.status !== 200 || !mdExport.text?.includes('Custody')) {
    fail('l2', `markdown export failed (${mdExport.status})`);
  } else {
    note('l2', 'markdown export ok');
  }

  const htmlExport = await api('GET', `/v1/reports/${reportId}/export?format=html`);
  if (htmlExport.status !== 200 || !htmlExport.text?.includes('Custody')) {
    fail('l2', `html export failed (${htmlExport.status})`);
  } else {
    note('l2', 'html export ok');
  }

  const pdfExport = await api('GET', `/v1/reports/${reportId}/export?format=pdf`);
  if (pdfExport.status !== 400 || pdfExport.json?.error !== 'unsupported_format') {
    fail('l2', `pdf boundary expected 400 unsupported_format got ${pdfExport.status}`);
  } else {
    note('l2', 'pdf boundary ok (400 unsupported_format)');
  }

  const listed = await api('GET', '/v1/reports');
  if (!(listed.json?.items ?? []).some((item) => item.id === reportId)) {
    fail('l2', `created report ${reportId} missing from list`);
  } else {
    note('l2', 'list includes created report');
  }

  return reportId;
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

async function runL3(fixture, reportId) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  for (const viewport of VIEWPORTS) {
    const { reportItems, reportExports } = await fetchFixture();
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#reports`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(1200);
      let bodyText = await page.locator('body').innerText();

      const requiredReports = [
        'Reports',
        'Generate report',
        'Generated reports',
        'Export custody',
        'PDF export is not available'
      ];
      for (const snippet of requiredReports) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /reports: missing "${snippet}"`);
        }
      }

      if (!bodyText.includes(`${reportItems.length} records`)) {
        fail('l1', `${viewport.name}: reports table badge mismatch (expected ${reportItems.length} records)`);
      }
      if (!bodyIncludesSnippet(bodyText, 'Exports')) {
        fail('l1', `${viewport.name}: exports metric label missing`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name} /reports: horizontal overflow`);

      if (viewport.name === 'desktop') {
        await page.locator('input[name="title"]').fill('PP-16 browser report');
        await page.locator('select[name="kind"]').selectOption('technical');

        const createResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/reports') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Generate report' }).click();
        const createdRes = await createResponse;
        if (!createdRes.ok()) {
          fail('l2', `browser create failed (${createdRes.status()})`);
        } else {
          const createdJson = await createdRes.json();
          note('l2', `browser create ok (${createdJson?.id ?? 'unknown'})`);
          await page.waitForTimeout(1000);
          bodyText = await page.locator('body').innerText();
          if (createdJson?.title && !bodyText.includes(createdJson.title)) {
            fail('l2', 'created report title not visible in table');
          }
        }

        const jsonBtn = page.getByRole('button', { name: 'JSON' }).first();
        const exportResponse = page.waitForResponse(
          (res) => res.url().includes('/export?format=json'),
          { timeout: 20000 }
        );
        await jsonBtn.click();
        const exportRes = await exportResponse;
        if (!exportRes.ok()) {
          fail('l2', `browser json export failed (${exportRes.status()})`);
        } else {
          note('l2', 'browser json export ok');
        }
        await page.waitForTimeout(800);
        bodyText = await page.locator('body').innerText();
        if (!bodyText.includes('content_sha256')) {
          fail('l3', 'desktop /reports: custody preview missing content_sha256 after JSON export');
        }
      }

      await page.goto(`${BASE_URL}/app#report-detail?id=${encodeURIComponent(reportId)}`, {
        waitUntil: 'networkidle',
        timeout: 45000
      });
      await page.waitForTimeout(1500);
      bodyText = await page.locator('body').innerText();

      const requiredDetail = [
        'Report detail',
        'Export formats',
        'Custody preview',
        'Export JSON',
        'Export Markdown',
        'Export HTML',
        'PDF export is not available'
      ];
      for (const snippet of requiredDetail) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /report-detail: missing "${snippet}"`);
        }
      }

      if (!bodyText.includes(reportId)) {
        fail('l1', `${viewport.name}: report-detail missing id ${reportId}`);
      }

      const detailOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (detailOverflow) fail('l3', `${viewport.name} /report-detail: horizontal overflow`);

      if (consoleErrors.filter((e) => !/favicon/i.test(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      note('l3', `${viewport.name}: reports + report-detail ok`);
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
  const reportId = await runL2(fixture);
  if (reportId) await runL3(fixture, reportId);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-16');
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