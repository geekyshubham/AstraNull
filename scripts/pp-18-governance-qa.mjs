#!/usr/bin/env node
/**
 * PAGE QA PP-18 — /notifications, /audit, /release-evidence (governance-pages)
 * L1 data fidelity, L2 backend actions + RBAC, L3 browser matrix + nav gates.
 */
import { canAccessRoute } from '../apps/web/react/src/lib/route-access.mjs';

const BASE_URL = process.env.ASTRANULL_BASE_URL ?? 'http://127.0.0.1:4320';

const ADMIN_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_admin',
  'x-role': 'admin',
  'Content-Type': 'application/json'
};

const VIEWER_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_viewer',
  'x-role': 'viewer',
  'Content-Type': 'application/json'
};

const AUDITOR_HEADERS = {
  'x-tenant-id': 'ten_demo',
  'x-user-id': 'usr_auditor',
  'x-role': 'auditor',
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

async function api(method, route, body, headers = ADMIN_HEADERS) {
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

function countDlqAttempts(events = []) {
  return events.flatMap((event) => Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [])
    .filter((attempt) => attempt.status === 'provider_failed_dlq').length;
}

async function fetchFixture() {
  const [notifications, audit, releaseEvidence, attestation] = await Promise.all([
    api('GET', '/v1/notifications'),
    api('GET', '/v1/audit-log'),
    api('GET', '/v1/production-release-evidence'),
    api('GET', '/v1/production-release-evidence/attestation')
  ]);
  const rules = notifications.json?.rules ?? [];
  const events = notifications.json?.events ?? [];
  const auditItems = audit.json?.items ?? [];
  const evidenceItems = releaseEvidence.json?.items ?? [];
  const attestationBody = attestation.json?.attestation ?? attestation.json ?? null;
  return {
    notifications,
    audit,
    releaseEvidence,
    attestation,
    rules,
    events,
    auditItems,
    evidenceItems,
    attestationBody,
    dlqCount: countDlqAttempts(events)
  };
}

async function runL1() {
  const fixture = await fetchFixture();
  const {
    notifications,
    audit,
    releaseEvidence,
    attestation,
    rules,
    events,
    auditItems,
    evidenceItems,
    attestationBody
  } = fixture;

  if (notifications.status !== 200) fail('l1', `GET /v1/notifications failed (${notifications.status})`);
  if (audit.status !== 200) fail('l1', `GET /v1/audit-log failed (${audit.status})`);
  if (releaseEvidence.status !== 200) fail('l1', `GET /v1/production-release-evidence failed (${releaseEvidence.status})`);
  if (attestation.status !== 200) fail('l1', `GET /v1/production-release-evidence/attestation failed (${attestation.status})`);

  note('l1', `rules=${rules.length} events=${events.length} dlq=${fixture.dlqCount}`);
  note('l1', `audit=${auditItems.length}`);
  note('l1', `release_evidence=${evidenceItems.length}`);
  note('l1', `attestation_signoff=${attestationBody?.signoff_status ?? 'unknown'}`);
  note('l1', `attestation_production_ready=${String(attestationBody?.production_ready ?? 'unknown')}`);

  if (attestationBody && typeof attestationBody.production_ready !== 'boolean') {
    fail('l1', 'attestation missing production_ready boolean');
  }

  for (const entry of auditItems.slice(0, 5)) {
    if (!entry.action) fail('l1', `audit entry missing action (${entry.id ?? 'unknown'})`);
    if (!entry.timestamp && !entry.created_at) {
      fail('l1', `audit entry missing timestamp (${entry.id ?? 'unknown'})`);
    }
  }

  return fixture;
}

async function runL2(fixture) {
  const viewerNotifications = await api('GET', '/v1/notifications', undefined, VIEWER_HEADERS);
  if (viewerNotifications.status !== 403) {
    fail('l2', `viewer notifications expected 403 got ${viewerNotifications.status}`);
  } else {
    note('l2', 'viewer notifications forbidden');
  }

  const viewerAudit = await api('GET', '/v1/audit-log', undefined, VIEWER_HEADERS);
  if (viewerAudit.status !== 403) {
    fail('l2', `viewer audit expected 403 got ${viewerAudit.status}`);
  } else {
    note('l2', 'viewer audit forbidden');
  }

  const auditorAudit = await api('GET', '/v1/audit-log', undefined, AUDITOR_HEADERS);
  if (auditorAudit.status !== 200) {
    fail('l2', `auditor audit expected 200 got ${auditorAudit.status}`);
  } else {
    note('l2', 'auditor audit allowed');
  }

  const auditorRelease = await api('GET', '/v1/production-release-evidence', undefined, AUDITOR_HEADERS);
  if (auditorRelease.status !== 200) {
    fail('l2', `auditor release evidence expected 200 got ${auditorRelease.status}`);
  } else {
    note('l2', 'auditor release evidence allowed');
  }

  if (!canAccessRoute('viewer', 'notifications')) note('l2', 'nav: viewer blocked from notifications');
  else fail('l2', 'nav: viewer should not access notifications route');
  if (!canAccessRoute('viewer', 'audit')) note('l2', 'nav: viewer blocked from audit');
  else fail('l2', 'nav: viewer should not access audit route');
  if (!canAccessRoute('auditor', 'audit')) fail('l2', 'nav: auditor should access audit');
  else note('l2', 'nav: auditor allowed audit');
  if (!canAccessRoute('auditor', 'release-evidence')) fail('l2', 'nav: auditor should access release-evidence');
  else note('l2', 'nav: auditor allowed release-evidence');

  const created = await api('POST', '/v1/notifications', {
    channel: 'webhook',
    enabled: true,
    triggers: ['finding.high_severity'],
    destination: 'https://hooks.example.invalid/pp18-qa'
  });
  if (created.status !== 200 && created.status !== 201) {
    fail('l2', `POST /v1/notifications failed (${created.status}) ${created.json?.error ?? ''}`);
  } else {
    note('l2', `created rule ${created.json?.id ?? 'unknown'}`);
  }

  const retries = await api('POST', '/v1/notifications/retries/process', { dry_run: true });
  if (retries.status !== 200) {
    fail('l2', `POST /v1/notifications/retries/process failed (${retries.status})`);
  } else {
    note('l2', `retry preview due_count=${retries.json?.due_count ?? 0}`);
  }

  const dlq = await api('POST', '/v1/notifications/dlq/redrive', { dry_run: true });
  if (dlq.status !== 200) {
    fail('l2', `POST /v1/notifications/dlq/redrive failed (${dlq.status})`);
  } else {
    note('l2', `dlq preview still_dlq_count=${dlq.json?.still_dlq_count ?? 0}`);
  }

  const listed = await api('GET', '/v1/notifications');
  const ruleCount = listed.json?.rules?.length ?? 0;
  if (ruleCount < (fixture.rules.length + 1)) {
    fail('l2', `notification rule count did not increase (${fixture.rules.length} -> ${ruleCount})`);
  } else {
    note('l2', `rules listed=${ruleCount}`);
  }

  const viewerWrite = await api('POST', '/v1/notifications/dlq/redrive', { dry_run: true }, VIEWER_HEADERS);
  if (viewerWrite.status !== 403) {
    fail('l2', `viewer dlq redrive expected 403 got ${viewerWrite.status}`);
  } else {
    note('l2', 'viewer dlq redrive forbidden');
  }
}

async function ensurePlaywright() {
  return import('playwright-core');
}

async function injectSession(page, role) {
  await page.goto(`${BASE_URL}/app`, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.evaluate((nextRole) => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify({
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: 'ten_demo',
      user_id: nextRole === 'viewer' ? 'usr_viewer' : nextRole === 'auditor' ? 'usr_auditor' : 'usr_admin',
      role: nextRole
    }));
  }, role);
}

async function sidebarLabels(page) {
  return page.locator('.nav-item span').allTextContents();
}

async function runL3() {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  for (const viewport of VIEWPORTS) {
    const fixture = await fetchFixture();
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page, 'admin');
      await page.goto(`${BASE_URL}/app#notifications`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.waitForTimeout(1800);
      let bodyText = await page.locator('body').innerText();

      for (const snippet of ['Rules', 'Recent events', 'DLQ', 'Delivery operations', 'Preview due retries']) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /notifications: missing "${snippet}"`);
        }
      }

      if (!bodyText.includes(String(fixture.rules.length))) {
        fail('l1', `${viewport.name}: rules metric mismatch (expected ${fixture.rules.length})`);
      }
      if (!bodyText.includes(String(fixture.events.length))) {
        fail('l1', `${viewport.name}: events metric mismatch (expected ${fixture.events.length})`);
      }

      if (viewport.name === 'desktop') {
        await page.locator('select[name="trigger"]').selectOption('high_scale.state_change');
        const createResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/notifications') && res.request().method() === 'POST',
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Add rule' }).click();
        const createdRes = await createResponse;
        if (!createdRes.ok()) {
          fail('l2', `browser create notification rule failed (${createdRes.status()})`);
        } else {
          note('l2', `browser create rule ok (${createdRes.status()})`);
        }
        await page.waitForTimeout(800);

        const retryResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/notifications/retries/process'),
          { timeout: 20000 }
        );
        await page.getByRole('button', { name: 'Preview due retries' }).click();
        const retryRes = await retryResponse;
        if (!retryRes.ok()) fail('l2', `browser retry preview failed (${retryRes.status()})`);
        else note('l2', 'browser retry preview ok');

        const dlqPreviewBtn = page.getByRole('button', { name: 'Preview DLQ redrive' });
        const dlqDisabled = await dlqPreviewBtn.isDisabled();
        if (fixture.dlqCount === 0) {
          if (!dlqDisabled) fail('l3', 'desktop: DLQ preview should be disabled when queue is empty');
          else note('l3', 'desktop: DLQ preview disabled with empty queue');
        } else {
          const dlqResponse = page.waitForResponse(
            (res) => res.url().includes('/v1/notifications/dlq/redrive'),
            { timeout: 20000 }
          );
          await dlqPreviewBtn.click();
          const dlqRes = await dlqResponse;
          if (!dlqRes.ok()) fail('l2', `browser dlq preview failed (${dlqRes.status()})`);
          else note('l2', 'browser dlq preview ok');
        }
      }

      await page.goto(`${BASE_URL}/app#audit`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.waitForTimeout(1500);
      bodyText = await page.locator('body').innerText();
      for (const snippet of ['Audit log', 'Filter', 'Custody chain only']) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /audit: missing "${snippet}"`);
        }
      }
      const sampleAction = fixture.auditItems[0]?.action;
      if (sampleAction && !bodyText.includes(sampleAction)) {
        fail('l1', `${viewport.name}: audit table missing action ${sampleAction}`);
      }

      await page.goto(`${BASE_URL}/app#release-evidence`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.waitForTimeout(1500);
      bodyText = await page.locator('body').innerText();
      for (const snippet of ['Gap ledger', 'Release evidence inventory', 'Attestation snapshot', 'Production ready']) {
        if (!bodyIncludesSnippet(bodyText, snippet)) {
          fail('l3', `${viewport.name} /release-evidence: missing "${snippet}"`);
        }
      }
      if (fixture.attestationBody?.signoff_status && !bodyText.includes(fixture.attestationBody.signoff_status)) {
        fail('l1', `${viewport.name}: attestation signoff_status missing (${fixture.attestationBody.signoff_status})`);
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow on release-evidence`);

      if (consoleErrors.filter((e) => !/favicon/i.test(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      note('l3', `${viewport.name}: admin governance routes ok`);
    } catch (error) {
      fail('l3', `${viewport.name} admin: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  for (const role of ['viewer', 'auditor']) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    try {
      await injectSession(page, role);
      await page.goto(`${BASE_URL}/app#dashboard`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.waitForTimeout(1500);
      const labels = (await sidebarLabels(page)).map((label) => label.trim());

      if (role === 'viewer') {
        if (labels.includes('Notifications')) fail('l3', 'viewer nav shows Notifications');
        else note('l3', 'viewer nav hides Notifications');
        if (labels.includes('Audit Log')) fail('l3', 'viewer nav shows Audit Log');
        else note('l3', 'viewer nav hides Audit Log');
        if (labels.includes('Release Evidence')) fail('l3', 'viewer nav shows Release Evidence');
        else note('l3', 'viewer nav hides Release Evidence');

        await page.goto(`${BASE_URL}/app#notifications`, { waitUntil: 'domcontentloaded', timeout: 45000 });
        await page.waitForTimeout(1200);
        const hash = await page.evaluate(() => window.location.hash.replace(/^#/, ''));
        if (hash === 'notifications') fail('l3', 'viewer hash bypass reached notifications');
        else note('l3', 'viewer hash guard redirects away from notifications');
      }

      if (role === 'auditor') {
        if (!labels.includes('Audit Log')) fail('l3', 'auditor nav missing Audit Log');
        else note('l3', 'auditor nav shows Audit Log');
        if (!labels.includes('Release Evidence')) fail('l3', 'auditor nav missing Release Evidence');
        else note('l3', 'auditor nav shows Release Evidence');

        await page.goto(`${BASE_URL}/app#audit`, { waitUntil: 'domcontentloaded', timeout: 45000 });
        await page.waitForTimeout(1200);
        const bodyText = await page.locator('body').innerText();
        if (!bodyIncludesSnippet(bodyText, 'Audit log')) fail('l3', 'auditor audit page unavailable');
        else note('l3', 'auditor audit page loads');
      }
    } catch (error) {
      fail('l3', `${role} rbac: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  const fixture = await runL1();
  await runL2(fixture);
  await runL3();

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-18');
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