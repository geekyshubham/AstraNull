#!/usr/bin/env node
/**
 * PP-12 /evidence page QA — L1 data fidelity, L2 custody verify + chain export, L3 browser matrix.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { buildEvidenceChainExport } from '../apps/web/react/src/lib/evidence-export.ts';
import { buildEvidenceCustodyManifest } from '../apps/web/react/src/lib/custody.ts';
import { sha256CanonicalJson } from '../src/lib/custody.mjs';

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

async function assertMetricValue(page, label, expected, viewportName) {
  const value = await page.evaluate((metricLabel) => {
    const cards = [...document.querySelectorAll('.metric-card')];
    for (const card of cards) {
      const labelEl = card.querySelector('span');
      const valueEl = card.querySelector('strong');
      if (labelEl?.textContent?.trim() === metricLabel && valueEl) {
        return valueEl.textContent?.trim() ?? '';
      }
    }
    return '';
  }, label);
  if (value !== String(expected)) {
    fail('l1', `${viewportName}: ${label} metric=${value || 'missing'} expected ${expected}`);
  }
}

function getString(item, keys, fallback = '') {
  if (!item || typeof item !== 'object') return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
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

async function ensureEvidenceFixture() {
  const listed = await api('GET', '/v1/evidence');
  if ((listed.json?.items ?? []).length > 0) {
    note('l2', `reusing ${listed.json.items.length} evidence record(s)`);
    return;
  }

  const groups = await api('GET', '/v1/target-groups');
  const group = groups.json?.items?.find((item) => !item.archived_at) ?? groups.json?.items?.[0];
  if (!group?.id) {
    fail('l2', 'no target group available for evidence fixture');
    return;
  }

  const detail = await api('GET', `/v1/target-groups/${group.id}`);
  const targetId = detail.json?.targets?.[0]?.id;
  if (!targetId) {
    fail('l2', `target group ${group.id} missing targets for evidence fixture`);
    return;
  }

  const checks = await api('GET', '/v1/checks');
  const safeCheck = checks.json?.items?.find((check) => check.safety_class === 'safe');
  if (!safeCheck?.check_id) {
    fail('l2', 'no safe check available for evidence fixture');
    return;
  }

  const created = await api('POST', '/v1/test-runs', {
    target_group_id: group.id,
    target_id: targetId,
    check_id: safeCheck.check_id
  });
  if (created.status !== 201 || !created.json?.run?.id) {
    if (created.status === 409) {
      note('l2', `run create returned 409 (${created.json?.error}) — reusing existing run activity`);
      return;
    }
    fail('l2', `POST /v1/test-runs for evidence fixture failed (${created.status})`);
    return;
  }

  await new Promise((resolve) => setTimeout(resolve, 1200));
  const evidence = await api('GET', '/v1/evidence');
  if ((evidence.json?.items ?? []).length === 0) {
    fail('l2', 'evidence fixture run completed without vault records');
  } else {
    note('l2', `seeded evidence via run ${created.json.run.id}`);
  }
}

async function runL1() {
  await ensureEvidenceFixture();

  const [evidence, runs, findings] = await Promise.all([
    api('GET', '/v1/evidence'),
    api('GET', '/v1/test-runs'),
    api('GET', '/v1/findings')
  ]);

  if (evidence.status !== 200) fail('l1', `GET /v1/evidence failed (${evidence.status})`);
  if (runs.status !== 200) fail('l1', `GET /v1/test-runs failed (${runs.status})`);
  if (findings.status !== 200) fail('l1', `GET /v1/findings failed (${findings.status})`);

  const evidenceItems = evidence.json?.items ?? [];
  const runItems = runs.json?.items ?? [];
  const findingItems = findings.json?.items ?? [];
  const linkedRunIds = new Set(
    evidenceItems.map((item) => getString(item, ['test_run_id'])).filter(Boolean)
  );
  const openFindings = findingItems.filter((item) => getString(item, ['status']) === 'open').length;

  note('l1', `evidence_records=${evidenceItems.length}`);
  note('l1', `linked_runs=${linkedRunIds.size}`);
  note('l1', `open_findings=${openFindings}`);

  for (const item of evidenceItems) {
    if (!item.id) fail('l1', 'evidence item missing id');
    if (!getString(item, ['label', 'kind', 'signal_type'])) {
      fail('l1', `evidence ${item.id} missing label/kind`);
    }
  }

  const chainPreview = buildEvidenceChainExport({
    evidence: evidenceItems,
    runs: runItems,
    findings: findingItems
  });
  if (chainPreview.payload.evidence_ids.length !== evidenceItems.length) {
    fail('l1', `chain export evidence_ids=${chainPreview.payload.evidence_ids.length} expected ${evidenceItems.length}`);
  }

  return {
    evidenceItems,
    runItems,
    findingItems,
    linkedRunIds,
    openFindings,
    chainPreview
  };
}

async function runL2(fixture) {
  const { evidenceItems, runItems, findingItems } = fixture;
  if (evidenceItems.length === 0) {
    note('l2', 'no evidence records — skipping detail/export checks');
    return;
  }

  const firstId = getString(evidenceItems[0], ['id']);
  const detail = await api('GET', `/v1/evidence/${firstId}`);
  if (detail.status !== 200) {
    fail('l2', `GET /v1/evidence/${firstId} failed (${detail.status})`);
  } else {
    note('l2', `detail ok (${firstId})`);
    if (getString(detail.json, ['id']) !== firstId) {
      fail('l2', `detail id mismatch for ${firstId}`);
    }
  }

  const verdicts = [];
  for (const run of runItems.slice(-20)) {
    const runId = getString(run, ['id']);
    if (!runId) continue;
    try {
      const runDetail = await api('GET', `/v1/test-runs/${runId}`);
      if (runDetail.status === 200 && runDetail.json?.verdict) {
        verdicts.push({ ...runDetail.json.verdict, test_run_id: runId });
      }
    } catch {
      /* partial chain */
    }
  }

  const exportData = buildEvidenceChainExport({
    evidence: evidenceItems,
    runs: runItems,
    verdicts,
    findings: findingItems
  });
  const custody = await buildEvidenceCustodyManifest(exportData.payload, 'ten_demo');
  const backendDigest = sha256CanonicalJson(exportData.payload);

  if (custody.content_canonicalization !== 'json-key-sorted-v1') {
    fail('l2', `custody canonicalization=${custody.content_canonicalization}`);
  }
  if (custody.content_sha256 !== backendDigest) {
    fail('l2', 'custody digest mismatch with backend canonicalization');
  }

  const verified = await api('POST', '/v1/custody/verify', {
    payload: exportData.payload,
    custody
  });
  if (verified.status !== 200) {
    fail('l2', `POST /v1/custody/verify failed (${verified.status})`);
  } else if (verified.json?.ok !== true) {
    fail('l2', `custody verify failed: ${verified.json?.verification?.error ?? 'unknown'}`);
  } else {
    note('l2', 'custody verify ok');
  }

  const tampered = await api('POST', '/v1/custody/verify', {
    payload: { ...exportData.payload, evidence_ids: ['tampered'] },
    custody
  });
  if (tampered.status !== 200 || tampered.json?.ok !== false) {
    fail('l2', 'tampered payload should fail custody verify');
  } else {
    note('l2', 'tampered payload rejected');
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

async function runL3(fixture) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const { evidenceItems, linkedRunIds, openFindings } = fixture;

  for (const viewport of VIEWPORTS) {
    const ready = await fetch(`${BASE_URL}/ready`).catch(() => null);
    if (!ready?.ok) {
      fail('l3', `${viewport.name}: server unavailable at ${BASE_URL}`);
      continue;
    }

    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#evidence`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.getByRole('heading', { name: 'Evidence Vault', level: 1 }).waitFor({ timeout: 20000 });
      await page.waitForTimeout(1200);
      const bodyText = await page.locator('body').innerText();

      const required = [
        'Evidence Vault',
        'Evidence records',
        'Linked runs',
        'Open findings',
        'Evidence chain export',
        'Evidence vault'
      ];
      for (const snippet of required) {
        if (!bodyText.toLowerCase().includes(snippet.toLowerCase())) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }

      await assertMetricValue(page, 'Evidence records', evidenceItems.length, viewport.name);
      await assertMetricValue(page, 'Linked runs', linkedRunIds.size, viewport.name);
      await assertMetricValue(page, 'Open findings', openFindings, viewport.name);

      if (evidenceItems.length > 0) {
        const firstLabel = getString(evidenceItems[0], ['label', 'kind', 'signal_type']);
        const firstId = getString(evidenceItems[0], ['id']);
        if (firstId && !bodyText.includes(firstId)) {
          fail('l1', `${viewport.name}: evidence id ${firstId} not visible in vault table`);
        }
        if (firstLabel && !bodyText.includes(firstLabel)) {
          fail('l1', `${viewport.name}: evidence kind/label "${firstLabel}" not visible`);
        }
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      if (consoleErrors.filter((e) => !isBenignConsoleError(e)).length) {
        fail('l3', `${viewport.name}: console errors ${consoleErrors.join('; ')}`);
      }
      if (pageErrors.length) fail('l3', `${viewport.name}: page errors ${pageErrors.join('; ')}`);

      if (viewport.name === 'desktop' && evidenceItems.length > 0) {
        await page.getByRole('heading', { name: 'Evidence detail' }).waitFor({ timeout: 15000 });
        note('l2', 'browser evidence detail panel visible');

        const verifyResponse = page.waitForResponse(
          (res) => res.url().includes('/v1/custody/verify') && res.request().method() === 'POST',
          { timeout: 25000 }
        );
        await page.getByRole('button', { name: 'Export chain JSON' }).click();
        const verifyRes = await verifyResponse;
        if (!verifyRes.ok()) {
          fail('l2', `browser custody verify failed (${verifyRes.status()})`);
        } else {
          const verifyJson = await verifyRes.json();
          if (verifyJson?.ok !== true) {
            fail('l2', `browser custody verify returned ok=false (${verifyJson?.verification?.error ?? 'unknown'})`);
          } else {
            note('l2', 'browser export chain + custody verify ok');
          }
        }

        await page.waitForTimeout(800);
        const afterExport = await page.locator('body').innerText();
        if (!afterExport.toLowerCase().includes('digest verified')) {
          fail('l3', 'desktop: custody preview missing "Digest verified" after export');
        }
      }

      note('l3', `${viewport.name}: evidence page render ok`);
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
  console.log('PAGE QA PP-12');
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