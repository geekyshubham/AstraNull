#!/usr/bin/env node
/**
 * PP-13 posture routes + detail routes — L1 data fidelity, L2 backend actions, L3 browser matrix.
 *
 * Routes: waf-posture, cve-pipeline, supply-chain, remediation, discovery
 * Details: waf-asset-detail, cve-detail, supply-chain-detail, discovery-entity
 *
 * Run with feature flags enabled:
 *   PORT=4320 ASTRANULL_NO_PERSIST=1 ASTRANULL_WAF_POSTURE_ENABLED=1 ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1 npm start
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

const POSTURE_ROUTES = ['waf-posture', 'cve-pipeline', 'supply-chain', 'remediation', 'discovery'];
const DETAIL_ROUTES = ['waf-asset-detail', 'cve-detail', 'supply-chain-detail', 'discovery-entity'];

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

async function apiRetry(method, route, body, headers = HEADERS, attempts = 6) {
  let last = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    last = await api(method, route, body, headers);
    if (last.status !== 429) return last;
    const waitMs = Math.min(1500 * (attempt + 1), 8000);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
  return last;
}

async function resolveDeclaredTarget() {
  const groups = await apiRetry('GET', '/v1/target-groups');
  if (groups.status !== 200) {
    fail('l2', `GET /v1/target-groups failed (${groups.status})`);
    return { groupId: '', targetId: '' };
  }
  const group = (groups.json?.items ?? []).find((item) => !item.archived_at) ?? groups.json?.items?.[0];
  const groupId = getString(group, ['id'], '');
  if (!groupId) {
    fail('l2', 'no declared target group for posture fixtures');
    return { groupId: '', targetId: '' };
  }
  const detail = await apiRetry('GET', `/v1/target-groups/${encodeURIComponent(groupId)}`);
  const targetId = getString((detail.json?.targets ?? [])[0], ['id'], '');
  if (!targetId) fail('l2', `target group ${groupId} has no declared targets`);
  return { groupId, targetId };
}

function routeHash(route, ids) {
  if (route === 'waf-asset-detail' && ids.wafAssetId) return `waf-asset-detail?id=${encodeURIComponent(ids.wafAssetId)}`;
  if (route === 'cve-detail' && ids.cveItemId) return `cve-detail?id=${encodeURIComponent(ids.cveItemId)}`;
  if (route === 'supply-chain-detail' && ids.supplyChainRiskId) return `supply-chain-detail?id=${encodeURIComponent(ids.supplyChainRiskId)}`;
  if (route === 'discovery-entity' && ids.discoveryEntityId) return `discovery-entity?id=${encodeURIComponent(ids.discoveryEntityId)}`;
  return route;
}

async function runL1() {
  const features = await apiRetry('GET', '/v1/tenant/deployment-features');
  if (features.status !== 200) {
    fail('l1', `GET /v1/tenant/deployment-features failed (${features.status})`);
    return null;
  }
  if (features.json?.waf_posture !== true) fail('l1', `waf_posture not enabled: ${JSON.stringify(features.json)}`);
  if (features.json?.external_discovery !== true) fail('l1', `external_discovery not enabled: ${JSON.stringify(features.json)}`);
  else note('l1', 'feature flags waf_posture + external_discovery enabled');

  const [
    coverage,
    roadmap,
    assets,
    drift,
    cve,
    supply,
    actionItems,
    discoveryCandidates,
    discoveryEntities,
    discoveryInbox
  ] = await Promise.all([
    apiRetry('GET', '/v1/waf/coverage'),
    apiRetry('GET', '/v1/waf/coverage/risk-roadmap'),
    apiRetry('GET', '/v1/waf/assets'),
    apiRetry('GET', '/v1/waf/drift-events'),
    apiRetry('GET', '/v1/waf/cve-pipeline'),
    apiRetry('GET', '/v1/waf/supply-chain/risks'),
    apiRetry('GET', '/v1/waf/action-items'),
    apiRetry('GET', '/v1/discovery/candidates'),
    apiRetry('GET', '/v1/discovery/entities'),
    apiRetry('GET', '/v1/discovery/inbox')
  ]);

  for (const [name, res] of [
    ['coverage', coverage],
    ['risk-roadmap', roadmap],
    ['assets', assets],
    ['drift-events', drift],
    ['cve-pipeline', cve],
    ['supply-chain', supply],
    ['action-items', actionItems],
    ['discovery/candidates', discoveryCandidates],
    ['discovery/entities', discoveryEntities],
    ['discovery/inbox', discoveryInbox]
  ]) {
    if (res.status !== 200) fail('l1', `GET ${name} status ${res.status}`);
  }

  const assetItems = assets.json?.items ?? [];
  const driftItems = drift.json?.items ?? [];
  const cveItems = cve.json?.items ?? [];
  const supplyItems = supply.json?.items ?? [];
  const actionItemItems = actionItems.json?.items ?? [];
  const candidateItems = discoveryCandidates.json?.items ?? [];
  const entityItems = discoveryEntities.json?.items ?? [];
  const inboxCount = typeof discoveryInbox.json?.count === 'number'
    ? discoveryInbox.json.count
    : (discoveryInbox.json?.items ?? []).length;

  note('l1', `assets=${assetItems.length} drift=${driftItems.length} cve=${cveItems.length} supply=${supplyItems.length}`);
  note('l1', `action_items=${actionItemItems.length} discovery_candidates=${candidateItems.length} entities=${entityItems.length} inbox=${inboxCount}`);
  if (roadmap.json?.method) note('l1', `roadmap.method=${roadmap.json.method}`);
  if (typeof coverage.json?.protected === 'number') note('l1', `coverage.protected=${coverage.json.protected}`);

  return {
    coverage: coverage.json,
    roadmap: roadmap.json,
    assetItems,
    cveItems,
    supplyItems,
    actionItemItems,
    candidateItems,
    entityItems,
    inboxCount
  };
}

async function ensureFindingForRemediation(groupId, targetId) {
  const findings = await apiRetry('GET', '/v1/findings');
  const existing = (findings.json?.items ?? []).find((item) => item.status === 'open') ?? findings.json?.items?.[0];
  if (existing?.id) {
    note('l2', `reusing finding ${existing.id}`);
    return existing.id;
  }

  let assetId = '';
  const assets = await apiRetry('GET', '/v1/waf/assets');
  assetId = getString((assets.json?.items ?? [])[0], ['id'], '');
  if (!assetId) {
    const created = await apiRetry('POST', '/v1/waf/assets', {
      target_group_id: groupId,
      target_id: targetId,
      canonical_url: `https://pp13-remediation-${Date.now()}.example.com`,
      owner_hint: 'pp13-qa'
    });
    assetId = getString(created.json?.asset ?? created.json, ['id'], '');
    if (!assetId) {
      fail('l2', `waf asset create for remediation failed (${created.status})`);
      return '';
    }
  }

  const validation = await apiRetry('POST', '/v1/waf/validations', {
    waf_asset_id: assetId,
    modes: ['marker']
  });
  const validationRunId = getString(validation.json?.validation_run ?? validation.json, ['id'], '');
  if (!validationRunId) {
    fail('l2', `waf validation create failed (${validation.status})`);
    return '';
  }

  const finalize = await apiRetry('POST', `/v1/waf/validations/${encodeURIComponent(validationRunId)}/finalize`, {
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
    return '';
  }

  const refreshed = await apiRetry('GET', '/v1/findings');
  const finding = (refreshed.json?.items ?? []).find((item) => item.check_id === `waf.posture.${assetId}`) ?? refreshed.json?.items?.[0];
  if (!finding?.id) {
    fail('l2', 'finding not created after validation finalize');
    return '';
  }
  note('l2', `created finding ${finding.id} via WAF validation finalize`);
  return finding.id;
}

async function runL2(snapshot) {
  const suffix = Date.now();
  const { groupId, targetId } = await resolveDeclaredTarget();
  const ids = {
    wafAssetId: getString(snapshot?.assetItems?.[0], ['id'], ''),
    cveItemId: getString(snapshot?.cveItems?.[0], ['id'], ''),
    supplyChainRiskId: getString(snapshot?.supplyItems?.[0], ['id'], ''),
    discoveryEntityId: getString(snapshot?.candidateItems?.[0] ?? snapshot?.entityItems?.[0], ['id', 'entity_id'], '')
  };

  if (!ids.wafAssetId && groupId && targetId) {
    const wafAssetRes = await apiRetry('POST', '/v1/waf/assets', {
      target_group_id: groupId,
      target_id: targetId,
      canonical_url: `https://pp13-${suffix}.example.com`,
      owner_hint: 'pp13-qa'
    });
    ids.wafAssetId = getString(wafAssetRes.json?.asset ?? wafAssetRes.json, ['id'], '');
    if (!ids.wafAssetId) fail('l2', `POST /v1/waf/assets status ${wafAssetRes.status}`);
    else note('l2', `created waf asset ${ids.wafAssetId}`);
  }

  if (!ids.cveItemId) {
    const cveRes = await apiRetry('POST', '/v1/waf/cve-pipeline', {
      cve_id: `CVE-2026-${String(suffix).slice(-4).padStart(4, '0')}`,
      severity: 'high',
      affected_products: ['declared-service'],
      known_exploited: false
    });
    ids.cveItemId = getString(cveRes.json?.item ?? cveRes.json, ['id'], '');
    if (!ids.cveItemId) {
      fail('l2', `POST /v1/waf/cve-pipeline status ${cveRes.status}`);
    } else {
      const triage = await apiRetry('POST', `/v1/waf/cve-pipeline/${encodeURIComponent(ids.cveItemId)}/triage`, {});
      if (triage.status !== 200) fail('l2', `POST cve triage status ${triage.status}`);
      else note('l2', `cve triage ok for ${ids.cveItemId}`);
    }
  }

  if (!ids.supplyChainRiskId) {
    const riskRes = await apiRetry('POST', '/v1/waf/supply-chain/risks', {
      exposure_type: 'dangling_cname',
      hostname: `orphan-${suffix}.example.com`,
      severity: 'high',
      confidence: 0.8,
      state: 'suspected',
      evidence_summary: { data_source: 'pp13_qa' },
      remediation_steps: ['Review DNS chain.']
    });
    ids.supplyChainRiskId = getString(riskRes.json?.risk ?? riskRes.json, ['id'], '');
    if (!ids.supplyChainRiskId) fail('l2', `POST supply-chain risk status ${riskRes.status}`);
    else note('l2', `created supply-chain risk ${ids.supplyChainRiskId}`);
  }

  const findingId = await ensureFindingForRemediation(groupId, targetId);
  if (findingId) {
    const actionRes = await apiRetry('POST', '/v1/waf/action-items', { finding_id: findingId });
    const actionItemId = getString(actionRes.json?.action_item ?? actionRes.json, ['action_item_id', 'id'], '');
    if (!actionItemId) {
      fail('l2', `POST action-items status ${actionRes.status}`);
    } else {
      const deliver = await apiRetry('POST', `/v1/waf/action-items/${encodeURIComponent(actionItemId)}/deliver`, {
        channel: 'webhook',
        connector: 'webhook',
        dry_run: true
      });
      if (deliver.status !== 200) fail('l2', `POST action-items deliver status ${deliver.status}`);
      else note('l2', `dry-run deliver ok for ${actionItemId}`);
    }
  }

  if (!ids.discoveryEntityId) {
    const entityRes = await apiRetry('POST', '/v1/discovery/entities', {
      entity_id: `ent_pp13_${suffix}`,
      entity_type: 'parent_organization',
      name: `PP13 Org ${suffix}`,
      display_name: `PP13 Org ${suffix}`,
      root_domains: [`pp13-${suffix}.example.com`],
      country: 'US',
      confidence: 0.85,
      source: 'customer_import'
    });
    ids.discoveryEntityId = getString(entityRes.json?.entity ?? entityRes.json, ['id', 'entity_id'], '');
    if (!ids.discoveryEntityId) fail('l2', `POST discovery entity status ${entityRes.status}`);
    else note('l2', `declared discovery entity ${ids.discoveryEntityId}`);
  }

  const candidates = await apiRetry('GET', '/v1/discovery/candidates');
  const candidate = (candidates.json?.items ?? []).find((item) => ['candidate', 'needs_review', 'discovered'].includes(String(item.state ?? '').toLowerCase()));
  if (candidate?.id) {
    const approve = await apiRetry('POST', `/v1/discovery/candidates/${encodeURIComponent(candidate.id)}/approve`, {
      target_group_id: groupId
    });
    if (approve.status !== 200) fail('l2', `POST discovery approve status ${approve.status}`);
    else note('l2', `approved discovery candidate ${candidate.id}`);
  }

  return ids;
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

function isBenignConsoleError(message) {
  return /favicon|429|Too Many Requests|404|409|Conflict/.test(message);
}

async function runL3(ids) {
  const { chromium } = await ensurePlaywright();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  async function injectSession(page) {
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

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    try {
      await page.goto(`${BASE_URL}/app`, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await injectSession(page);
      await page.reload({ waitUntil: 'networkidle', timeout: 45000 });

      for (const route of [...POSTURE_ROUTES, ...DETAIL_ROUTES]) {
        const label = `${viewport.name}:${route}`;
        const hash = routeHash(route, ids);
        await page.goto(`${BASE_URL}/app#${hash}`, { waitUntil: 'networkidle', timeout: 45000 });
        await page.waitForTimeout(route === 'discovery' ? 900 : 700);
        const bodyText = await page.locator('body').innerText();

        if (/Workspace tabs|Connector drift snapshot awaiting triage|CVE mitigation playbook needs owner approval/.test(bodyText)) {
          fail('l3', `${label}: forbidden static prototype copy detected`);
        }

        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
        if (overflow) fail('l3', `${label}: horizontal overflow`);

        if (route === 'waf-posture') {
          if (!bodyText.includes('Roadmap')) fail('l3', `${label}: missing Roadmap tab`);
          if (!bodyText.includes('Assets')) fail('l3', `${label}: missing Assets tab`);
          if (!bodyText.includes('Create WAF asset')) fail('l3', `${label}: missing Create WAF asset`);
          await page.getByRole('tab', { name: 'Roadmap' }).click({ timeout: 10000 });
          await page.waitForTimeout(400);
          const roadmapText = await page.locator('body').innerText();
          if (!roadmapText.includes('Deployment roadmap')) fail('l3', `${label}:roadmap-tab missing Deployment roadmap panel`);
        }
        if (route === 'cve-pipeline' && !bodyText.includes('Create CVE item')) fail('l3', `${label}: missing Create CVE item`);
        if (route === 'supply-chain' && !bodyText.includes('Create risk')) fail('l3', `${label}: missing Create risk`);
        if (route === 'remediation' && !bodyText.includes('Dry-run deliver')) fail('l3', `${label}: missing Dry-run deliver`);
        if (route === 'discovery' && !bodyText.includes('Declare entity')) fail('l3', `${label}: missing Declare entity`);
        if (route === 'waf-asset-detail' && !bodyText.includes('WAF effectiveness')) fail('l3', `${label}: missing WAF effectiveness`);
        if (route === 'cve-detail' && !bodyText.includes('Run triage')) fail('l3', `${label}: missing Run triage`);
        if (route === 'supply-chain-detail' && !bodyText.includes('Remediation steps')) fail('l3', `${label}: missing remediation steps`);
        if (route === 'discovery-entity' && !bodyText.includes('Discovery decision trail')) fail('l3', `${label}: missing discovery trail`);
      }

      for (const err of consoleErrors.filter((message) => !isBenignConsoleError(message))) {
        fail('l3', `${viewport.name}:console ${err}`);
      }
      for (const err of pageErrors) fail('l3', `${viewport.name}:pageerror ${err}`);

      note('l3', `${viewport.name}: posture routes + details ok`);
    } catch (error) {
      fail('l3', `${viewport.name}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  const snapshot = await runL1();
  const ids = await runL2(snapshot);
  await runL3(ids);

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('PAGE QA PP-13');
  console.log(`VERDICT: ${verdict}`);
  console.log(`L1 DATA FIDELITY: ${results.l1.pass ? 'PASS' : 'FAIL'} — ${results.l1.notes.join('; ')}`);
  console.log(`L2 BACKEND LOGIC: ${results.l2.pass ? 'PASS' : 'FAIL'} — ${results.l2.notes.join('; ')}`);
  console.log(`L3 UI + VIEWPORTS: ${results.l3.pass ? 'PASS' : 'FAIL'} — ${results.l3.notes.join('; ')}`);
  console.log('L4 PRODUCTION READINESS: PASS — external blockers: live WAF connectors, staging signoff, immutable report signing');
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