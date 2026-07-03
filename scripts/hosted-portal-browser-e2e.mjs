#!/usr/bin/env node
/**
 * Browser E2E for hosted/local customer portal: landing → login → app pages → staff admin.
 * Requires: playwright-core (installed on demand).
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const CUSTOMER_ROUTES = [
  'dashboard',
  'onboarding',
  'environments',
  'target-groups',
  'agents',
  'checks',
  'runs',
  'findings',
  'evidence',
  'waf-posture',
  'cve-pipeline',
  'supply-chain',
  'remediation',
  'discovery',
  'high-scale',
  'soc',
  'reports',
  'notifications',
  'audit',
  'release-evidence',
  'settings',
];

const STAFF_ROUTES = ['overview', 'signup-queue', 'tenants', 'approvals', 'audit'];

const MJS_ASSETS = ['/login.mjs', '/portal-auth.mjs', '/staff-login.mjs', '/internal-admin.js', '/verdict-explanation.mjs'];

function parseArgs(argv = []) {
  const opts = { baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? 'http://127.0.0.1:3000', help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = argv[++i];
  }
  return opts;
}

function ensurePlaywrightCore() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });
  if (check.status !== 0) {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT,
      stdio: 'inherit',
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core for browser E2E');
  }
}

/**
 * @param {string} baseUrl
 */
async function runBrowserE2e(baseUrl) {
  const { chromium } = await import('playwright-core');
  const failures = [];
  const consoleErrors = [];

  function fail(step, detail) {
    failures.push({ step, detail });
    console.error('FAIL', step, detail);
  }

  let browser;
  const launchOpts = { headless: true };
  try {
    browser = await chromium.launch({ ...launchOpts, channel: 'chrome' });
  } catch {
    try {
      browser = await chromium.launch(launchOpts);
    } catch {
      browser = await chromium.connectOverCDP('ws://127.0.0.1:9222');
    }
  }
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  try {
    for (const asset of MJS_ASSETS) {
      const resp = await page.request.get(baseUrl + asset);
      const ct = resp.headers()['content-type'] ?? '';
      if (!resp.ok()) {
        if (asset === '/staff-login.mjs' || asset === '/internal-admin.js') continue;
        fail(`asset ${asset}`, `HTTP ${resp.status()}`);
        continue;
      }
      if (asset.endsWith('.mjs') && !/javascript/i.test(ct)) {
        fail(`mime ${asset}`, ct || 'missing content-type');
      }
    }

    await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle', timeout: 60000 });
    const landingText = await page.locator('body').innerText();
    if (!/No-access-first|AstraNull/i.test(landingText)) {
      fail('landing page', landingText.slice(0, 120));
    }

    await page.goto(`${baseUrl}/signup`, { waitUntil: 'networkidle', timeout: 30000 });
    const signupText = await page.locator('body').innerText();
    if (!/Request an AstraNull account|approval-gated/i.test(signupText)) {
      fail('signup page', signupText.slice(0, 120));
    }

    await page.goto(`${baseUrl}/login`, { waitUntil: 'networkidle', timeout: 60000 });
    const loginHint = await page.locator('#loginCredentialsHint').isVisible().catch(() => false);
    if (!loginHint) {
      fail('login credentials hint', 'missing #loginCredentialsHint');
    }

    await page.click('#loginSubmit');
    try {
      await page.waitForURL((url) => url.pathname === '/app' || url.pathname.startsWith('/app'), { timeout: 30000 });
    } catch {
      const errText = await page.locator('#loginError').textContent().catch(() => '');
      fail('login redirect', `still on ${page.url()}${errText ? ` error=${errText}` : ''}`);
    }

    if (await page.locator('#loginError').isVisible().catch(() => false)) {
      fail('login error visible', await page.locator('#loginError').textContent());
    }

    try {
      await page.waitForFunction(() => {
        const nav = document.querySelectorAll('#nav a');
        const view = document.getElementById('view');
        return nav.length > 3 && view && !view.textContent.includes('Sign-in required');
      }, { timeout: 30000 });
    } catch {
      const viewText = await page.locator('#view').innerText().catch(() => '');
      fail('dashboard load', viewText.slice(0, 180));
    }

    for (const route of CUSTOMER_ROUTES) {
      await page.goto(`${baseUrl}/app#${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(600);
      const viewText = await page.locator('#view').innerText();
      if (/Sign-in required|Unable to load this page: unauthorized/i.test(viewText)) {
        fail(`route ${route}`, viewText.slice(0, 180));
        continue;
      }
      if (/Unable to load this page/i.test(viewText) && !/Your current role cannot access/i.test(viewText)) {
        fail(`route ${route}`, viewText.slice(0, 180));
      }
    }

    await page.goto(`${baseUrl}/internal/admin/login`, { waitUntil: 'networkidle' });
    const staffModuleResp = await page.request.get(`${baseUrl}/staff-login.mjs`);
    const staffCt = staffModuleResp.headers()['content-type'] ?? '';
    if (!/javascript/i.test(staffCt)) {
      fail('staff-login.mjs mime', staffCt || 'missing content-type');
    }

    await page.waitForSelector('#staffLoginSubmit', { timeout: 15000 });
    await page.click('#staffLoginSubmit');
    try {
      await page.waitForURL((url) => url.pathname === '/internal/admin' || url.pathname.startsWith('/internal/admin'), {
        timeout: 30000,
      });
    } catch {
      const errText = await page.locator('#staffLoginError').textContent().catch(() => '');
      fail('staff login redirect', `still on ${page.url()}${errText ? ` error=${errText}` : ''}`);
    }

    try {
      await page.waitForFunction(() => {
        const view = document.getElementById('staffView');
        return view && !view.textContent.includes('Sign-in required');
      }, { timeout: 30000 });
    } catch {
      const viewText = await page.locator('#staffView').innerText().catch(() => '');
      fail('staff overview load', viewText.slice(0, 180));
    }

    for (const route of STAFF_ROUTES) {
      await page.goto(`${baseUrl}/internal/admin#${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      const viewText = await page.locator('#staffView').innerText();
      if (/Sign-in required|Could not load/i.test(viewText) && !/0/.test(viewText)) {
        fail(`staff route ${route}`, viewText.slice(0, 180));
      }
    }
  } finally {
    await browser.close();
  }

  if (consoleErrors.length) {
    const moduleMimeErrors = consoleErrors.filter((e) => /Failed to load module script/i.test(e));
    if (moduleMimeErrors.length) {
      fail('module script mime console errors', moduleMimeErrors.join(' | '));
    }
    console.log('console errors:', JSON.stringify(consoleErrors.slice(0, 10), null, 2));
  }

  const result = { ok: failures.length === 0, failures, consoleErrorCount: consoleErrors.length };
  console.log(JSON.stringify(result, null, 2));
  return failures.length === 0 ? 0 : 1;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/hosted-portal-browser-e2e.mjs [--base-url URL]');
    return 0;
  }
  ensurePlaywrightCore();
  const baseUrl = String(opts.baseUrl).replace(/\/$/, '');
  return runBrowserE2e(baseUrl);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().then((code) => process.exit(code ?? 0));
}