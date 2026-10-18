import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { assertPortalInitialLoad } from '../../helpers/portal-browser-failures.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { addWafNfwDemoEvidence, rebaseDemoStoreTimestamps } from '../../../scripts/seed-dev-portal-demo.mjs';
import {
  getPortalPlaywrightBaseUrl,
  seedPortalPlaywrightStore,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import { injectPortalDevHeadersSession, waitForPortalRouteSettled } from '../../helpers/portal-playwright-session.mjs';

/** T8: honest efficacy, control declarations, rule coverage and probe evidence against the dev-json backend. */

const TARGET = PORTAL_BASELINE_IDS.targetId;

function seedWafNfw(store) {
  applyPortalBaselineReadinessBoost(store, { observedAt: PORTAL_BASELINE_IDS.frozenAt });
  addWafNfwDemoEvidence(store, PORTAL_BASELINE_IDS);
  rebaseDemoStoreTimestamps(store);
}

async function open(page, hash) {
  await page.goto(`${getPortalPlaywrightBaseUrl()}/app#${hash}`, { waitUntil: 'networkidle', timeout: 60_000 });
  await waitForPortalRouteSettled(page);
}

async function expectNoAxeViolations(page, selector) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).include(selector).analyze();
  const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
  expect(blocking.map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => node.target) }))).toEqual([]);
}

test.describe('WAF/NFW truthful results, declarations and rule coverage (T8)', () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(180000);
    await startPortalPlaywrightServer({ liveSource: true, mutate: seedWafNfw, env: { ASTRANULL_PROBE_MODE: 'simulation' } });
    const warm = await browser.newPage();
    try {
      await injectPortalDevHeadersSession(warm);
      await assertPortalInitialLoad(warm, getPortalPlaywrightBaseUrl());
    } finally {
      await warm.close();
    }
  });
  test.beforeEach(async ({ page }) => {
    test.setTimeout(90000);
    seedPortalPlaywrightStore(seedWafNfw);
    await injectPortalDevHeadersSession(page);
  });
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('efficacy separates managed rule markers from custom canary rules and never claims attack classes', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}`);
    const efficacy = page.locator('.td-efficacy');
    await expect(efficacy.getByText('Managed rules enforced:')).toBeVisible();
    await expect(efficacy.getByText('Custom canary rules enforced:')).toHaveCount(0);
    await expect(efficacy).toContainText('inconclusive');
    await efficacy.getByText('How this is decided', { exact: true }).click();
    await expect(efficacy).toContainText('Installed rule tokens and placements are not bound to these checks');
    await expect(efficacy).toContainText('do not verify custom-rule action or attack-class coverage');
    await expect(page.locator('body')).not.toContainText(/attack classes/i);
  });

  test('control declarations validate inline, save, and guard unsaved changes', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=controls`);
    const form = page.locator('.cd');
    await expect(form.getByRole('heading', { name: 'Control declarations' })).toBeVisible();
    await expect(form.getByRole('textbox', { name: 'Port for rule 1' })).toHaveValue('22');

    await form.getByRole('button', { name: 'Add rule' }).click();
    const port = form.getByRole('textbox', { name: 'Port for rule 5' });
    await port.fill('70000');
    await form.getByRole('button', { name: 'Save declarations' }).click();
    const summary = page.locator('.cd-error-summary');
    await expect(summary).toBeFocused();
    await expect(summary).toContainText('Network rule 5: port');
    await expect(port).toHaveAttribute('aria-invalid', 'true');

    page.once('dialog', (dialog) => void dialog.dismiss());
    await page.getByRole('tab', { name: /Validate/ }).click();
    await expect(form.getByRole('heading', { name: 'Control declarations' })).toBeVisible();

    await port.fill('2222');
    await form.getByRole('button', { name: 'Save declarations' }).click();
    await expect(page.locator('.cd-status')).toContainText('Declarations saved');
    const saved = await page.evaluate(async (id) => {
      const session = JSON.parse(sessionStorage.getItem('astranull.portal.session.v1') ?? '{}');
      const response = await fetch(`/v1/targets/${id}/control-declarations`, { headers: { 'x-tenant-id': session.tenant_id, 'x-user-id': session.user_id, 'x-role': session.role } });
      return response.json();
    }, TARGET);
    expect(saved.network_policy.map((rule) => rule.port)).toEqual([22, 3389, 443, 5900, 2222]);
    expect(saved.revision).toBe(1);
    await expectNoAxeViolations(page, '.cd');
  });

  test('a concurrent save keeps the draft, explains the conflict and never overwrites silently', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=controls`);
    const form = page.locator('.cd');
    await form.getByRole('button', { name: 'Add rule' }).click();
    await form.getByRole('textbox', { name: 'Port for rule 5' }).fill('8443');

    const theirs = await page.evaluate(async (id) => {
      const session = JSON.parse(sessionStorage.getItem('astranull.portal.session.v1') ?? '{}');
      const headers = { 'x-tenant-id': session.tenant_id, 'x-user-id': 'usr_other_admin', 'x-role': session.role, 'content-type': 'application/json' };
      const current = await fetch(`/v1/targets/${id}/control-declarations`, { headers });
      const doc = await current.json();
      const body = { version: 1, network_policy: [...doc.network_policy, { protocol: 'udp', port: 161, action: 'deny', address_family: 'any' }], waf: doc.waf, origin: doc.origin, perspectives: doc.perspectives };
      const missing = await fetch(`/v1/targets/${id}/control-declarations`, { method: 'PUT', headers, body: JSON.stringify(body) });
      const saved = await fetch(`/v1/targets/${id}/control-declarations`, { method: 'PUT', headers: { ...headers, 'If-Match': current.headers.get('etag') }, body: JSON.stringify(body) });
      return { missing: missing.status, saved: saved.status, etag: saved.headers.get('etag') };
    }, TARGET);
    expect(theirs).toEqual({ missing: 428, saved: 200, etag: '"decl-r1"' });

    await form.getByRole('button', { name: 'Save declarations' }).click();
    const conflict = page.locator('.cd-conflict');
    await expect(conflict).toBeFocused();
    await expect(conflict).toContainText('Someone else saved these controls');
    await expect(conflict).toContainText('Review their version, then re-apply your changes');
    await expect(form.getByRole('textbox', { name: 'Port for rule 5' })).toHaveValue('8443');
    await expect(form.getByRole('button', { name: 'Save declarations' })).toBeDisabled();

    await conflict.getByRole('button', { name: 'Load latest' }).click();
    const diff = conflict.getByRole('table');
    await expect(diff.getByRole('row', { name: /Network policy/ })).toContainText('not in your draft: UDP 161 deny');
    await expect(diff.getByRole('row', { name: /Network policy/ })).toContainText('not in their version: TCP 8443 deny');
    await expect(conflict).toContainText('usr_other_admin');
    await expectNoAxeViolations(page, '.cd-conflict');

    await conflict.getByRole('button', { name: 'Keep my draft and review' }).click();
    await expect(page.locator('.cd-conflict')).toHaveCount(0);
    await expect(form.getByRole('textbox', { name: 'Port for rule 5' })).toHaveValue('8443');
    await form.getByRole('button', { name: 'Save declarations' }).click();
    await expect(page.locator('.cd-status')).toContainText('Declarations saved');
    const stored = await page.evaluate(async (id) => {
      const session = JSON.parse(sessionStorage.getItem('astranull.portal.session.v1') ?? '{}');
      const response = await fetch(`/v1/targets/${id}/control-declarations`, { headers: { 'x-tenant-id': session.tenant_id, 'x-user-id': session.user_id, 'x-role': session.role } });
      return response.json();
    }, TARGET);
    expect(stored.revision).toBe(2);
    expect(stored.network_policy.map((rule) => `${rule.protocol}/${rule.port}`)).toEqual(['tcp/22', 'tcp/3389', 'tcp/443', 'tcp/5900', 'tcp/8443']);
  });

  test('rule coverage shows honest reasons and declaration CTAs', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=coverage`);
    const panel = page.locator('.rc-panel');
    await expect(panel.getByRole('row', { name: /ICMP policy/ })).toContainText('Not assessable');
    await expect(panel.getByRole('row', { name: /ICMP policy/ })).toContainText('AstraNull sends no ICMP probes');
    await expect(panel.getByRole('row', { name: /Egress filtering/ })).toContainText('Out of scope');
    const cta = panel.getByRole('link', { name: 'Declare a rate-limit canary route' });
    await expect(cta).toHaveAttribute('href', new RegExp(`id=${TARGET}&tab=controls&section=rate_limit`));
    await expect(panel.getByRole('row', { name: /Inbound TCP allow and deny/ })).toContainText('Fail');
    await expectNoAxeViolations(page, '.rc-panel');
  });

  test('new surfaces pass axe in the light theme too', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('astranull.theme', 'light'));
    await open(page, `target-detail?id=${TARGET}&tab=coverage`);
    await expect(page.locator('.rc-table').first()).toBeVisible();
    await expectNoAxeViolations(page, '.rc-panel');
    await open(page, `target-detail?id=${TARGET}&tab=controls`);
    await expect(page.locator('.cd-form')).toBeVisible();
    await expectNoAxeViolations(page, '.cd');
    await open(page, `target-detail?id=${TARGET}`);
    await expectNoAxeViolations(page, '.td-efficacy');
    await open(page, 'run-detail?id=run_wafnfw_3');
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    await expect(page.locator('.poe').first()).toBeVisible();
    await expectNoAxeViolations(page, '.poe');
  });

  test('run evidence explains normalization gaps and network outcomes in plain words', async ({ page }) => {
    await open(page, 'run-detail?id=run_wafnfw_9');
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    await expect(page.getByText(/Normalization gap/)).toBeVisible();

    await open(page, 'run-detail?id=run_wafnfw_11');
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    await expect(page.getByText('Handshake completed').first()).toBeVisible();
    await expect(page.getByText('IPv4 and IPv6 differ').first()).toBeVisible();
  });

  test('per-port deny results, the request budget and perspective authentication are explicit', async ({ page }) => {
    await open(page, 'run-detail?id=run_wafnfw_11');
    await page.getByRole('tab', { name: 'Probe evidence' }).click();
    const ports = page.getByRole('region', { name: 'Result per declared deny port' });
    await expect(ports.getByRole('row', { name: /TCP 22/ })).toContainText('Violates your deny rule');
    await expect(ports.getByRole('row', { name: /TCP 3389/ })).toContainText('No violation seen');
    await expect(page.locator('.poe')).toContainText('Not probed within the safe request budget: 5900');
    await expect(page.locator('.poe')).toContainText('Perspective not authenticated — result cannot prove an allowlist gap');
    await expectNoAxeViolations(page, '.poe');
  });

  test('re-checking a verdict fetches on demand and explains a grading version gap', async ({ page }) => {
    const replayCalls = [];
    page.on('request', (request) => { if (/\/v1\/test-runs\/[^/]+\/verdict-replay$/.test(new URL(request.url()).pathname)) replayCalls.push(request.url()); });
    const consoleErrors = [];
    page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    await open(page, 'run-detail?id=run_wafnfw_12');
    expect(replayCalls).toEqual([]);
    const replay = page.getByRole('region', { name: 'Re-check this verdict' });
    await replay.getByRole('button', { name: 'Re-check this verdict with current rules' }).click();
    // This historical custom-token run has no attested probe I/O; preserve its stored verdict, not its old projection.
    await expect(replay.getByRole('status')).toContainText('Would now be Inconclusive');
    await expect(replay.getByRole('status')).toContainText('stored as Protected');
    await expect(replay.getByRole('status')).toContainText('no attested probe I/O');
    await expect(replay.getByRole('status')).toContainText('The stored verdict is not changed');
    await expect(replay.getByRole('status')).toContainText('Grading rules changed — re-run to restore credit');
    expect(replayCalls).toHaveLength(1);
    await expectNoAxeViolations(page, '.vr');

    await open(page, 'finding-detail?id=fnd_wafnfw_deny_22');
    const findingReplay = page.getByRole('region', { name: 'Re-check this verdict' });
    await findingReplay.getByRole('button', { name: 'Re-check this verdict with current rules' }).click();
    await expect(findingReplay.getByRole('status')).toContainText('Unchanged');
    expect(consoleErrors).toEqual([]);
  });
  test('server refusal codes label not-runnable checks and deep-link to the right Controls section', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=validate`);
    const requirements = page.locator('.td-catalog-requirements');
    await requirements.locator('summary').click();
    const udp = requirements.locator('li', { hasText: 'nfw.declared_deny_udp.safe' });
    await expect(udp).toContainText('Needs a declared UDP deny rule');
    await expect(udp.getByRole('link', { name: 'Declare a denied UDP port' })).toHaveAttribute('href', new RegExp(`id=${TARGET}&tab=controls&section=network`));
    const limit = requirements.locator('li', { hasText: 'nfw.connection_limit.safe' });
    await expect(limit).toContainText('Needs a declared connection limit');
    await expect(limit.getByRole('link', { name: 'Declare a connection limit' })).toHaveAttribute('href', /section=connection_limits/);
    await expect(requirements).not.toContainText('_required');
  });

  test('origin lockdown explains it also needs one active origin relation', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=controls&section=origin`);
    const origin = page.locator('#cd-section-origin');
    await expect(origin).toContainText('needs both this declaration and one active origin relation');
    const status = origin.locator('.cd-origin-relation');
    await expect(status).toContainText('No active origin relation');
    await expect(status.getByRole('link', { name: 'Open Origin relations' })).toHaveAttribute('href', /tab=overview&section=origin-relations/);
    await expectNoAxeViolations(page, '#cd-section-origin');
  });

  test('a replay explains why historical stored responses cannot be re-graded', async ({ page }) => {
    await open(page, 'run-detail?id=run_wafnfw_7');
    const oldFeatures = page.getByRole('region', { name: 'Re-check this verdict' });
    await oldFeatures.getByRole('button', { name: 'Re-check this verdict with current rules' }).click();
    await expect(oldFeatures.getByRole('status')).toContainText('Would now be Inconclusive');
    await expect(oldFeatures.getByRole('status')).toContainText('stored as Gap found');
    await expect(oldFeatures.getByRole('status')).toContainText('no attested probe I/O');
    await expect(oldFeatures.getByRole('status')).toContainText('Only the verdict logic was re-applied');
    await expect(oldFeatures.getByRole('status')).not.toContainText('Re-graded with current signatures');

    await open(page, 'run-detail?id=run_wafnfw_12');
    const logicOnly = page.getByRole('region', { name: 'Re-check this verdict' });
    await logicOnly.getByRole('button', { name: 'Re-check this verdict with current rules' }).click();
    await expect(logicOnly.getByRole('status')).toContainText('Only the verdict logic was re-applied');
    await expect(logicOnly.getByRole('status')).toContainText('did not store response details');
    await expectNoAxeViolations(page, '.vr');
  });

  test('a fix-verified finding names how the fix was proved', async ({ page }) => {
    await open(page, 'finding-detail?id=fnd_wafnfw_deny_3389_fixed');
    await expect(page.locator('.finding-closure-basis')).toContainText('Fixed — violation no longer reproduced (same perspective, ≥2 agreeing samples, all declared ports probed)');
    await open(page, 'finding-detail?id=fnd_wafnfw_xss_fixed');
    await expect(page.locator('.finding-closure-basis')).toContainText('Fixed — passing retest');
  });

  test('fix-verified rows in the findings list show how each fix was proved', async ({ page }) => {
    await open(page, 'findings?status=fix_verified');
    await expect(page.locator('tr', { hasText: 'Declared-denied TCP 3389' }).first()).toContainText('No longer reproduced');
    await expect(page.locator('tr', { hasText: 'Managed XSS marker' }).first()).toContainText('Passing retest');
  });

  test('the rate-limit canary keeps the action the WAF should take at the limit', async ({ page }) => {
    await open(page, `target-detail?id=${TARGET}&tab=controls&section=rate_limit`);
    const section = page.locator('#cd-section-rate_limit');
    await section.getByRole('checkbox', { name: 'Declare a rate-limit canary route' }).check();
    await section.getByRole('textbox', { name: 'Path' }).fill('/rl-canary');
    await section.getByRole('textbox', { name: 'Threshold (requests)' }).fill('5');
    await section.getByRole('textbox', { name: 'Window (seconds)' }).fill('10');
    const group = section.getByRole('group', { name: 'When the limit is reached, the WAF should:' });
    await expect(group.getByRole('radio', { name: /^Block A block/ })).toBeChecked();
    await group.getByRole('radio', { name: /^Block or challenge/ }).check();
    await page.locator('.cd').getByRole('button', { name: 'Save declarations' }).click();
    await expect(page.locator('.cd-status')).toContainText('Declarations saved');
    const saved = await page.evaluate(async (id) => {
      const session = JSON.parse(sessionStorage.getItem('astranull.portal.session.v1') ?? '{}');
      const response = await fetch(`/v1/targets/${id}/control-declarations`, { headers: { 'x-tenant-id': session.tenant_id, 'x-user-id': session.user_id, 'x-role': session.role } });
      return response.json();
    }, TARGET);
    expect(saved.waf.rate_limit_canary.expected_action).toBe('block_or_challenge');
    await page.reload({ waitUntil: 'networkidle' });
    await waitForPortalRouteSettled(page);
    await expect(page.locator('#cd-section-rate_limit').getByRole('radio', { name: /^Block or challenge/ })).toBeChecked();
    await expectNoAxeViolations(page, '#cd-section-rate_limit');
  });
});
