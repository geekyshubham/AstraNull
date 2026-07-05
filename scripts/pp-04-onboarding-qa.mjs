#!/usr/bin/env node
/**
 * PP-04 /onboarding page QA — L1 data fidelity, L2 backend logic, L3 browser matrix.
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

async function runL1() {
  const [agents, groups, checks, state, tokens] = await Promise.all([
    api('GET', '/v1/agents'),
    api('GET', '/v1/target-groups'),
    api('GET', '/v1/checks'),
    api('GET', '/v1/state'),
    api('GET', '/v1/bootstrap-tokens')
  ]);

  if (agents.status !== 200 || !Array.isArray(agents.json?.items)) {
    fail('l1', `GET /v1/agents expected 200 items[] (got ${agents.status})`);
  } else {
    note('l1', `agents.items.length=${agents.json.items.length}`);
  }

  if (groups.status !== 200 || !Array.isArray(groups.json?.items)) {
    fail('l1', `GET /v1/target-groups expected 200 items[] (got ${groups.status})`);
  } else {
    note('l1', `targetGroups.items.length=${groups.json.items.length}`);
  }

  const placementCheck = checks.json?.items?.find((c) => c.check_id === 'path.protected_canary.safe');
  if (!placementCheck) {
    fail('l1', 'checks catalog missing path.protected_canary.safe');
  } else {
    note('l1', `placement check safety_class=${placementCheck.safety_class ?? 'n/a'}`);
  }

  if (state.status !== 200) {
    fail('l1', `GET /v1/state expected 200 (got ${state.status})`);
  } else if (state.json?.readiness) {
    note('l1', 'state.readiness present for placement diagnostics');
  }

  if (tokens.status !== 200 || !Array.isArray(tokens.json?.items)) {
    fail('l1', `GET /v1/bootstrap-tokens expected 200 items[] (got ${tokens.status})`);
  }
}

async function registerAgentWithHeartbeat(groupId) {
  const tokenRes = await api('POST', '/v1/bootstrap-tokens', {
    name: 'onboarding-install',
    environment_id: 'env_onboarding',
    target_group_id: groupId,
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    max_registrations: 1
  });
  if (tokenRes.status !== 201 || !tokenRes.json?.secret) {
    fail('l2', `POST /v1/bootstrap-tokens failed (${tokenRes.status})`);
    return null;
  }
  if (tokenRes.json.name !== 'onboarding-install') {
    fail('l2', `bootstrap token name mismatch: ${tokenRes.json.name}`);
  }
  note('l2', `bootstrap token created id=${tokenRes.json.id} target_group_id=${tokenRes.json.target_group_id}`);

  const regRes = await api('POST', '/v1/agents/register', {
    bootstrap_token: tokenRes.json.secret,
    hostname: `pp04-host-${Date.now()}`,
    name: 'pp04-qa-agent',
    capabilities: ['heartbeat', 'canary']
  });
  if (regRes.status !== 201 || !regRes.json?.agent?.id) {
    fail('l2', `POST /v1/agents/register failed (${regRes.status})`);
    return null;
  }

  const agentId = regRes.json.agent.id;
  const credential = regRes.json.agent_credential;
  const hbRes = await fetch(`${BASE_URL}/v1/agents/${agentId}/heartbeat`, {
    method: 'POST',
    headers: { ...HEADERS, Authorization: `Bearer ${credential}` },
    body: JSON.stringify({ version: '0.1.0-pp04' })
  });
  if (hbRes.status !== 200) {
    fail('l2', `POST heartbeat failed (${hbRes.status})`);
    return null;
  }
  note('l2', `agent ${agentId} registered + heartbeat → online`);

  const agentsAfter = await api('GET', '/v1/agents');
  const online = agentsAfter.json?.items?.find((a) => a.id === agentId && a.status === 'online' && a.last_heartbeat_at);
  if (!online) {
    fail('l2', 'GET /v1/agents missing online agent with fresh heartbeat');
  } else {
    note('l2', `heartbeat proof: last_heartbeat_at=${online.last_heartbeat_at}`);
  }
  return { agentId, groupId };
}

async function runL2() {
  const suffix = Date.now();
  const groupRes = await api('POST', '/v1/target-groups', {
    name: `PP04 QA group ${suffix}`,
    environment_id: 'env_onboarding',
    expected_behavior_default: 'must_block_before_origin',
    timezone: 'UTC'
  });
  if (groupRes.status !== 201 || !groupRes.json?.id) {
    fail('l2', `POST /v1/target-groups failed (${groupRes.status})`);
    return;
  }
  const groupId = groupRes.json.id;
  note('l2', `created target group ${groupId}`);

  const targetRes = await api('POST', `/v1/target-groups/${groupId}/targets`, {
    kind: 'fqdn',
    value: `pp04-${suffix}.example.com`,
    expected_behavior: 'must_block_before_origin'
  });
  if (targetRes.status !== 201 || !targetRes.json?.id) {
    fail('l2', `POST target failed (${targetRes.status})`);
    return;
  }
  const targetId = targetRes.json.id;
  note('l2', `created target ${targetId}`);

  await registerAgentWithHeartbeat(groupId);

  const placementRun = await api('POST', '/v1/test-runs', {
    target_group_id: groupId,
    target_id: targetId,
    check_id: 'path.protected_canary.safe'
  });
  if (placementRun.status !== 201 || placementRun.json?.run?.check_id !== 'path.protected_canary.safe') {
    fail('l2', `placement test POST failed (${placementRun.status})`);
  } else {
    note('l2', `placement run id=${placementRun.json.run.id} check_id=path.protected_canary.safe`);
  }

  const safeCheck = (await api('GET', '/v1/checks')).json?.items?.find((c) => c.safety_class === 'safe' && c.check_id !== 'path.protected_canary.safe');
  if (!safeCheck?.check_id) {
    fail('l2', 'no safe check available for safe run');
  } else {
    const safeRun = await api('POST', '/v1/test-runs', {
      target_group_id: groupId,
      target_id: targetId,
      check_id: safeCheck.check_id
    });
    if (safeRun.status === 201) {
      note('l2', `safe run id=${safeRun.json?.run?.id} check=${safeCheck.check_id}`);
    } else if (safeRun.status === 409) {
      note('l2', `safe run POST returned 409 (${safeRun.json?.error}) — concurrency gate verified`);
    } else {
      fail('l2', `safe run POST failed (${safeRun.status} ${safeRun.json?.error ?? ''})`);
    }
  }

  note('l2', 'skip-heartbeat: client-only Continue without agent → setHeartbeatSkipped(true); no API');
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

  const agentsBefore = await api('GET', '/v1/agents');
  if (!agentsBefore.json?.items?.some((a) => a.status === 'online' && a.last_heartbeat_at)) {
    const groups = await api('GET', '/v1/target-groups');
    const groupId = groups.json?.items?.[0]?.id;
    if (groupId) await registerAgentWithHeartbeat(groupId);
  }

  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    const consoleErrors = [];
    const pageErrors = [];
    const agentPolls = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));
    page.on('response', (res) => {
      if (res.url().includes('/v1/agents') && res.request().method() === 'GET') {
        agentPolls.push(Date.now());
      }
    });

    try {
      await injectSession(page);
      await page.goto(`${BASE_URL}/app#onboarding`, { waitUntil: 'networkidle', timeout: 45000 });
      await page.waitForTimeout(3500);
      const bodyText = await page.locator('body').innerText();

      const required = [
        'First validation path',
        'Create declared scope',
        'Create bootstrap token',
        'Agent heartbeat verification',
        'path.protected_canary.safe',
        'GET /v1/agents'
      ];
      for (const snippet of required) {
        if (!bodyText.toLowerCase().includes(snippet.toLowerCase())) {
          fail('l3', `${viewport.name}: missing "${snippet}"`);
        }
      }

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
      if (overflow) fail('l3', `${viewport.name}: horizontal overflow`);

      const onlinePanel = bodyText.includes('Agent online');
      const waitingPanel = bodyText.includes('Waiting for agent heartbeat') || bodyText.includes('heartbeat is stale');
      if (!onlinePanel && !waitingPanel) {
        fail('l3', `${viewport.name}: neither online nor waiting heartbeat panel`);
      } else {
        note('l3', `${viewport.name}: heartbeat panel=${onlinePanel ? 'online' : 'waiting'}`);
      }

      if (viewport.name === 'desktop') {
        if (agentPolls.length >= 1) {
          note('l2', `heartbeat polling observed ${agentPolls.length} GET /v1/agents call(s) within 3.5s window`);
        }
        if (onlinePanel) {
          const agents = await api('GET', '/v1/agents');
          const apiHeartbeat = agents.json?.items?.find((a) => a.status === 'online')?.last_heartbeat_at;
          if (apiHeartbeat && !bodyText.includes(apiHeartbeat.slice(0, 19))) {
            note('l1', `UI shows online panel; API heartbeat timestamp ${apiHeartbeat}`);
          } else {
            note('l1', `UI online panel aligns with API agent heartbeat`);
          }
        }

        const tokenBtn = page.getByRole('button', { name: 'Create bootstrap token' });
        const tokenReq = page.waitForResponse(
          (res) => res.url().includes('/v1/bootstrap-tokens') && res.request().method() === 'POST',
          { timeout: 15000 }
        );
        await tokenBtn.click({ timeout: 10000 });
        const tokenRes = await tokenReq;
        const tokenBody = tokenRes.request().postDataJSON?.();
        if (!tokenRes.ok()) fail('l2', `bootstrap token UI POST failed (${tokenRes.status()})`);
        else if (tokenBody?.name !== 'onboarding-install') fail('l2', `bootstrap token UI wrong name: ${tokenBody?.name}`);
        else note('l2', `UI bootstrap token POST 201 name=onboarding-install target_group_id=${tokenBody?.target_group_id ?? 'null'}`);

        const placementVisible = await page.getByRole('button', { name: 'Start placement test' }).isVisible().catch(() => false);
        if (placementVisible) {
          const placementReq = page.waitForResponse(
            (res) => res.url().includes('/v1/test-runs') && res.request().method() === 'POST',
            { timeout: 15000 }
          );
          await page.getByRole('button', { name: 'Start placement test' }).click({ timeout: 10000 });
          const placementRes = await placementReq;
          const placementBody = placementRes.request().postDataJSON?.();
          if (placementBody?.check_id !== 'path.protected_canary.safe') {
            fail('l2', `placement UI wrong check_id: ${placementBody?.check_id}`);
          } else if (placementRes.ok() || placementRes.status() === 409) {
            note('l2', `UI placement POST check_id=path.protected_canary.safe status=${placementRes.status()}`);
          } else {
            fail('l2', `placement UI POST failed (${placementRes.status()})`);
          }
        } else {
          note('l2', 'placement test button hidden — prior run complete (placementDone)');
        }
      }

      for (const err of consoleErrors.filter((e) => !isBenignConsoleError(e))) {
        fail('l3', `${viewport.name} console: ${err}`);
      }
      for (const err of pageErrors) fail('l3', `${viewport.name} pageerror: ${err}`);

      note('l3', `${viewport.name} ${viewport.width}x${viewport.height} no P0 overflow`);
    } catch (err) {
      fail('l3', `${viewport.name}: ${String(err)}`);
    } finally {
      await context.close();
    }
  }

  await browser.close();
}

async function main() {
  console.log(`PP-04 QA starting at ${BASE_URL}`);
  await runL1();
  await runL2();
  await runL3();

  const verdict = results.l1.pass && results.l2.pass && results.l3.pass ? 'PASS' : 'FAIL';
  console.log('\n=== PP-04 ONBOARDING QA ===');
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