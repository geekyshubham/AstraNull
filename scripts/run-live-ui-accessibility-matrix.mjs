#!/usr/bin/env node
/**
 * Executes live customer-portal accessibility probes and writes matrix evidence input.
 */
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_PAGES } from './ui-accessibility-matrix-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUT = path.join(REPO_ROOT, 'output/release-evidence/ui-accessibility-matrix-input.json');
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(', ');

const PAGE_ROUTES = {
  dashboard: 'dashboard',
  test_runs: 'runs',
  soc_console: 'soc',
  high_scale_request: 'high-scale',
  reports_export_custody_preview: 'reports',
  findings: 'findings',
};

function parseArgs(argv = []) {
  const opts = {
    baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? 'http://127.0.0.1:3000',
    out: DEFAULT_OUT,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = argv[++i];
    else if (arg === '--out') opts.out = argv[++i];
  }
  return opts;
}

function ensurePlaywrightCore() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (check.status !== 0) {
    spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], { cwd: REPO_ROOT, stdio: 'inherit' });
  }
}

export const ACCESSIBILITY_RUNNER_IDENTITY = 'accessibility-runner@astranull.invalid';

export async function loginCustomer(page, baseUrl) {
  const configUrl = `${baseUrl}/v1/public/site-config`;
  let response;
  try {
    response = await page.request.get(configUrl, {
      headers: { accept: 'application/json' },
      timeout: 30000,
    });
  } catch (error) {
    throw new Error(
      `Accessibility runner could not inspect the staging login mode at ${configUrl}; refusing credentialless login: ${error.message}`,
    );
  }
  if (!response.ok()) {
    throw new Error(
      `Accessibility runner could not inspect the staging login mode at ${configUrl} (HTTP ${response.status()}); refusing credentialless login.`,
    );
  }

  let config;
  try {
    config = await response.json();
  } catch {
    throw new Error('Accessibility runner received invalid public site config; refusing credentialless login.');
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('Accessibility runner received invalid public site config; refusing credentialless login.');
  }

  const authMode = String(config.auth_mode ?? '').trim();
  const bundledStaging = authMode === 'oidc-jwt' && config.bundled_staging_login_enabled === true;
  if (authMode !== 'dev-headers' && !bundledStaging) {
    throw new Error(
      `Accessibility runner refuses credentialless login for auth_mode=${authMode || 'unknown'} with bundled_staging_login_enabled=${config.bundled_staging_login_enabled === true}; use dev-headers or the explicitly enabled bundled staging bypass. Enterprise password and real IdP login require a credentialed harness.`,
    );
  }

  await page.goto(`${baseUrl}/login`, { waitUntil: 'networkidle', timeout: 60000 });

  if (bundledStaging && config.password_login_enabled === true) {
    try {
      await page.locator('details.auth-bypass > summary').click({ timeout: 30000 });
      await page.locator('#login-password').waitFor({ state: 'detached', timeout: 30000 });
    } catch {
      throw new Error('Bundled staging login was advertised, but its credentialless staging bypass control was unavailable.');
    }
  }

  await page.locator('#login-user-id').fill(ACCESSIBILITY_RUNNER_IDENTITY, { timeout: 30000 });
  await page.getByRole('button', { name: 'Continue to portal', exact: true }).click({ timeout: 30000 });
  await page.waitForURL((url) => url.pathname === '/app', { timeout: 30000 });
  await page.waitForSelector('main.main', { state: 'visible', timeout: 30000 });
}

function emptyIssueCounts() {
  return { critical: 0, serious: 0, moderate: 0, minor: 0 };
}

function axeIssueCounts(violations = []) {
  const counts = emptyIssueCounts();
  for (const violation of violations) {
    const impact = String(violation.impact ?? 'minor').toLowerCase();
    counts[impact in counts ? impact : 'minor'] += 1;
  }
  return counts;
}

export function summarizeAccessibilityChecks({
  routeAuthorized,
  axeCompleted = false,
  axeIssues = emptyIssueCounts(),
  keyboardCompleted = false,
  keyboardIssues = [],
  screenReaderCompleted = false,
  screenReaderIssues = [],
} = {}) {
  const issues = { ...emptyIssueCounts(), ...axeIssues };
  if (!routeAuthorized) issues.serious += 1;
  if (routeAuthorized && (!keyboardCompleted || keyboardIssues.length > 0)) issues.moderate += 1;
  if (routeAuthorized && (!screenReaderCompleted || screenReaderIssues.length > 0)) issues.moderate += 1;

  if (!routeAuthorized) {
    return {
      axe_status: 'skip',
      keyboard_status: 'skip',
      screen_reader_status: 'skip',
      issues,
    };
  }

  return {
    axe_status: axeCompleted && issues.critical === 0 && issues.serious === 0 ? 'pass' : 'fail',
    keyboard_status: keyboardCompleted && keyboardIssues.length === 0 ? 'pass' : 'fail',
    screen_reader_status: screenReaderCompleted && screenReaderIssues.length === 0 ? 'pass' : 'fail',
    issues,
  };
}

const KEYBOARD_SAMPLE_LIMIT = 6;
const KEYBOARD_FOCUS_SENTINEL_ID = 'astranull-keyboard-focus-sentinel';

export async function runKeyboardChecks(page) {
  const seen = new Set();
  let firstSignature = '';
  let sampledStops = 0;
  let missingIndicators = 0;
  let invalidStops = 0;
  let navigationStalled = false;
  let originReady = false;

  try {
    originReady = await page.evaluate((sentinelId) => {
      document.getElementById(sentinelId)?.remove();
      const sentinel = document.createElement('span');
      sentinel.id = sentinelId;
      sentinel.tabIndex = 0;
      sentinel.setAttribute('aria-hidden', 'true');
      Object.assign(sentinel.style, {
        position: 'fixed',
        width: '1px',
        height: '1px',
        left: '-10000px',
        top: '0',
        opacity: '0',
        pointerEvents: 'none',
      });
      document.body.prepend(sentinel);
      sentinel.focus({ preventScroll: true });
      window.scrollTo(0, 0);
      return document.activeElement === sentinel;
    }, KEYBOARD_FOCUS_SENTINEL_ID);

    while (originReady && sampledStops < KEYBOARD_SAMPLE_LIMIT) {
      await page.keyboard.press('Tab');
      const state = await page.evaluate(({ selector, sentinelId }) => {
        const active = document.activeElement;
        const sentinel = document.getElementById(sentinelId);
        if (active === sentinel) return { boundary: 'sentinel' };
        if (!active || active === document.body || active === document.documentElement) {
          return { boundary: 'document' };
        }

        const style = getComputedStyle(active);
        const rect = active.getBoundingClientRect();
        const outlineVisible = style.outlineStyle !== 'none' && Number.parseFloat(style.outlineWidth) > 0;
        return {
          boundary: null,
          focusable: active.matches(selector),
          visible: style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0,
          indicator: outlineVisible || (style.boxShadow !== 'none' && style.boxShadow !== ''),
          signature: String(Array.from(document.querySelectorAll('*')).indexOf(active)),
        };
      }, { selector: FOCUSABLE_SELECTOR, sentinelId: KEYBOARD_FOCUS_SENTINEL_ID });

      if (state.boundary) break;
      if (state.signature && seen.has(state.signature)) {
        if (state.signature !== firstSignature || seen.size === 1) navigationStalled = true;
        break;
      }

      sampledStops += 1;
      if (!state.focusable || !state.visible) invalidStops += 1;
      if (!state.indicator) missingIndicators += 1;
      if (!state.signature) {
        navigationStalled = true;
        break;
      }
      if (!firstSignature) firstSignature = state.signature;
      seen.add(state.signature);
    }
  } finally {
    await page.evaluate((sentinelId) => {
      document.getElementById(sentinelId)?.remove();
    }, KEYBOARD_FOCUS_SENTINEL_ID);
  }

  const issues = [];
  if (!originReady) issues.push('Tab navigation did not establish a deterministic focus origin');
  if (sampledStops === 0) issues.push('No reachable keyboard-focusable control found');
  if (invalidStops > 0) issues.push(`${invalidStops} sampled tab stop(s) were hidden or not focusable`);
  if (missingIndicators > 0) issues.push(`${missingIndicators} sampled tab stop(s) lacked a visible focus indicator`);
  if (navigationStalled) issues.push('Tab navigation did not advance through distinct controls');
  return { completed: true, checks: sampledStops, issues };
}

async function runScreenReaderSemanticChecks(page) {
  return page.evaluate(() => {
    const issues = [];
    let checks = 0;
    const main = document.querySelector('main.main, main');
    checks += 1;
    if (!main) issues.push('Missing main landmark');

    checks += 1;
    const heading = main?.querySelector('h1');
    if (!heading?.textContent?.trim()) issues.push('Main landmark has no named level-one heading');

    checks += 1;
    if (!document.title.trim()) issues.push('Document title is empty');

    function explicitName(element) {
      const label = element.getAttribute('aria-label')?.trim();
      if (label) return label;
      const labelledBy = element.getAttribute('aria-labelledby')?.trim();
      if (!labelledBy) return '';
      return labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? '')
        .filter(Boolean)
        .join(' ');
    }

    const namedRegions = Array.from(document.querySelectorAll('[role="region"], [role="tabpanel"]'))
      .filter((element) => element.getAttribute('aria-hidden') !== 'true');
    for (const region of namedRegions) {
      checks += 1;
      if (!explicitName(region)) issues.push(`${region.getAttribute('role')} is missing an accessible name`);
    }

    return { completed: true, checks, issues };
  });
}

async function runViewportChecks(page, baseUrl, pageId, route, viewport) {
  const width = viewport === 'mobile' ? 390 : 1280;
  const height = viewport === 'mobile' ? 844 : 800;
  await page.setViewportSize({ width, height });
  await page.goto(`${baseUrl}/app#${route}`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.waitForSelector('main.main', { state: 'visible', timeout: 30000 });
  await page.waitForTimeout(600);

  const viewText = await page.locator('main.main').innerText();
  const unauthorizedText = /Sign-in required|Unable to load this page: unauthorized/i.test(viewText);
  const landedRoute = new URL(page.url()).hash.replace(/^#/, '').split('?')[0];
  const routeAuthorized = !unauthorizedText && landedRoute === route;

  let axeCompleted = false;
  let axeIssues = emptyIssueCounts();
  let keyboard = { completed: false, checks: 0, issues: [] };
  let screenReader = { completed: false, checks: 0, issues: [] };
  const notes = [];

  if (routeAuthorized) {
    try {
      const axeResults = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
      axeIssues = axeIssueCounts(axeResults.violations);
      axeCompleted = true;
      notes.push(`axe executed (${axeResults.violations.length} violation rules)`);
    } catch {
      notes.push('axe execution failed');
    }

    try {
      keyboard = await runKeyboardChecks(page);
      notes.push(`keyboard traversal executed (${keyboard.checks} checks)`);
      if (keyboard.issues.length > 0) notes.push(`keyboard issues: ${keyboard.issues.join('; ')}`);
    } catch {
      notes.push('keyboard traversal failed to execute');
    }

    try {
      screenReader = await runScreenReaderSemanticChecks(page);
      notes.push(`screen-reader semantics executed (${screenReader.checks} checks; no assistive-technology session claimed)`);
    } catch {
      notes.push('screen-reader semantic checks failed to execute');
    }
  } else {
    notes.push(unauthorizedText
      ? 'route required re-auth; accessibility checks skipped'
      : `route redirected to #${landedRoute || '(none)'}; accessibility checks skipped`);
  }

  const summary = summarizeAccessibilityChecks({
    routeAuthorized,
    axeCompleted,
    axeIssues,
    keyboardCompleted: keyboard.completed,
    keyboardIssues: keyboard.issues,
    screenReaderCompleted: screenReader.completed,
    screenReaderIssues: screenReader.issues,
  });

  return {
    page: pageId,
    viewport,
    browser: 'chromium',
    ...summary,
    captured_at: new Date().toISOString(),
    notes: notes.join('; '),
  };
}

export async function runLiveUiAccessibilityMatrix(opts) {
  ensurePlaywrightCore();
  const { chromium } = await import('playwright-core');
  const baseUrl = String(opts.baseUrl).replace(/\/$/, '');
  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const context = await browser.newContext();
  const page = await context.newPage();
  const runs = [];
  try {
    await loginCustomer(page, baseUrl);
    for (const pageId of REQUIRED_PAGES) {
      const route = PAGE_ROUTES[pageId] ?? pageId;
      for (const viewport of ['desktop', 'mobile']) {
        runs.push(await runViewportChecks(page, baseUrl, pageId, route, viewport));
      }
    }
  } finally {
    await context.close();
    await browser.close();
  }

  const failed = runs.filter((run) => run.axe_status !== 'pass'
    || run.keyboard_status !== 'pass'
    || run.screen_reader_status !== 'pass');
  if (failed.length > 0) {
    throw new Error(`UI accessibility matrix failed for ${failed.map((run) => (
      `${run.page}/${run.viewport} (axe=${run.axe_status}, keyboard=${run.keyboard_status}, screen-reader=${run.screen_reader_status}; ${run.notes})`
    )).join(', ')}`);
  }

  const evidence = {
    schema_version: 1,
    artifact_type: 'ui_accessibility_matrix_input',
    environment: 'staging',
    evidence_uri: 'evidence://ui/accessibility-matrix/staging',
    runs,
    pages: Object.fromEntries(
      REQUIRED_PAGES.map((pageId) => [pageId, { runs: runs.filter((run) => run.page === pageId) }]),
    ),
  };

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(evidence, null, 2)}\n`);
  return { evidence, out: opts.out, runs };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/run-live-ui-accessibility-matrix.mjs [--base-url URL] [--out file]');
    return 0;
  }
  const result = await runLiveUiAccessibilityMatrix(opts);
  console.log(`run-live-ui-accessibility-matrix: ok (${result.runs.length} runs) wrote ${result.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`run-live-ui-accessibility-matrix: ${err.message}`);
      process.exit(1);
    },
  );
}
