import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { getStore } from '../../../src/store.mjs';
import { buildPortalActionInventory, assertSourcePortalAction } from '../../helpers/portal-action-coverage.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const inventory = buildPortalActionInventory();
const confirm = (page) => page.locator('dialog.modal-confirm:not(.form-modal)[open]');
const receipt = (testInfo, handler, state, assertions) => assertSourcePortalAction(testInfo, inventory, { owner: 'SettingsPage', handler, kind: 'form-keyboard' }, state, assertions, { route: 'settings' });

async function openSettings(page, tab) {
  await injectPortalDevHeadersSession(page);
  await gotoPortalRoute(page, 'settings', getPortalPlaywrightBaseUrl());
  if (tab) await page.getByRole('tab', { name: tab, exact: true }).click();
}
async function dismissOneTimeSecret(page) {
  const secret = page.getByRole('region', { name: /New service account secret|New secret for/ });
  await secret.getByRole('checkbox').check();
  await secret.getByRole('button', { name: 'Dismiss secret', exact: true }).click();
  await expect(secret).toBeHidden();
}

test.describe('settings automation and vault finite action states', () => {
  test.beforeAll(async () => { await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64') } }); });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  test('service account invalid scopes, delayed failed create, retry, one-time reveal/copy/ack, rotate/revoke cancel and accepted reload', async ({ page, context }, testInfo) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    // Relative expiry is derived from client Date at submit; fix Date so retry equality is deterministic.
    await page.clock.setFixedTime(new Date());
    const writes = [];
    let releaseFailure;
    const failure = new Promise((resolve) => { releaseFailure = resolve; });
    await page.route('**/v1/service-accounts', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      writes.push(route.request().postDataJSON());
      if (writes.length === 1) { await failure; return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'synthetic_account_outage', message: 'Synthetic account admission outage' }) }); }
      return route.continue();
    });
    await openSettings(page, 'Access');
    const panel = page.locator('#settings-sections-panel-access');
    const form = panel.locator('form').first();
    await form.getByLabel('Name', { exact: true }).fill('Synthetic automation owner');
    await form.getByRole('combobox', { name: /^Role/ }).selectOption('viewer');
    await form.getByRole('checkbox', { name: /tenant:read/ }).uncheck();
    await form.getByRole('checkbox', { name: /evidence:read/ }).uncheck();
    await form.getByLabel('Name', { exact: true }).press('Enter');
    await receipt(testInfo, 'handleCreateServiceAccount', 'invalid', async () => {
      await expect(page.getByRole('alert')).toContainText('Select at least one scope.'); expect(writes).toEqual([]);
      return ['Keyboard submission with no role-held scope selected is rejected before API writes'];
    });
    await expect(form.getByRole('checkbox', { name: /test_run:execute/ })).toHaveCount(0);
    await form.getByRole('checkbox', { name: /report:read/ }).check();
    await form.getByRole('button', { name: 'Create service account', exact: true }).click();
    try {
      await receipt(testInfo, 'handleCreateServiceAccount', 'busy', async () => {
        await expect.poll(() => writes.length).toBe(1);
        await expect(form.getByRole('button', { name: /Create service account|Working/ })).toBeDisabled();
        await form.getByLabel('Name', { exact: true }).press('Enter');
        await page.waitForTimeout(100); expect(writes).toHaveLength(1);
        return ['Delayed service-account create disables submit; Enter during busy issues no duplicate POST'];
      });
    } finally { releaseFailure(); }
    await expect(page.getByRole('alert')).toContainText('Service is temporarily unavailable. Try again shortly.');
    await expect(form.getByLabel('Name', { exact: true })).toHaveValue('Synthetic automation owner');
    const createResponse = page.waitForResponse((response) => /\/v1\/service-accounts$/.test(response.url()) && response.request().method() === 'POST' && response.status() === 201);
    await form.getByRole('button', { name: 'Create service account', exact: true }).click();
    const created = await (await createResponse).json();
    await receipt(testInfo, 'handleCreateServiceAccount', 'error-retry', async () => {
      expect(writes).toHaveLength(2); expect(writes[1]).toEqual(writes[0]); expect(created.scopes).toEqual(['report:read']);
      const secret = page.getByRole('region', { name: 'New service account secret', exact: true });
      await expect(secret.getByLabel('One-time secret')).not.toContainText(created.secret);
      await secret.getByRole('button', { name: 'Reveal', exact: true }).click();
      await expect(secret.getByLabel('One-time secret')).toHaveText(created.secret);
      await secret.getByRole('button', { name: 'Copy secret', exact: true }).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(created.secret);
      await secret.getByRole('button', { name: 'Hide', exact: true }).click();
      await expect(secret.getByLabel('One-time secret')).not.toContainText(created.secret);
      await expect(secret.getByRole('button', { name: 'Dismiss secret', exact: true })).toBeDisabled();
      return ['Explicit retry sends identical scoped payload and one accepted account; one-time value masked/reveal/copy/hide and acknowledgement-gated dismissal'];
    });
    await dismissOneTimeSecret(page);
    const mutations = [];
    page.on('request', (request) => { if (request.method() === 'POST' && new RegExp(`/v1/service-accounts/${created.id}/(?:rotate|revoke)$`).test(request.url())) mutations.push(new URL(request.url()).pathname); });
    const row = panel.locator('tbody tr').filter({ hasText: 'Synthetic automation owner' });
    await row.getByRole('button', { name: 'Rotate secret for Synthetic automation owner' }).click();
    await confirm(page).getByRole('button', { name: 'Cancel', exact: true }).click(); expect(mutations).toEqual([]);
    await row.getByRole('button', { name: 'Rotate secret for Synthetic automation owner' }).click();
    const rotationResponse = page.waitForResponse((response) => response.url().endsWith(`/v1/service-accounts/${created.id}/rotate`) && response.status() === 200);
    await confirm(page).getByRole('button', { name: 'Rotate secret', exact: true }).click();
    const rotated = await (await rotationResponse).json(); expect(rotated.secret).not.toBe(created.secret);
    await dismissOneTimeSecret(page);
    await row.getByRole('button', { name: 'Revoke Synthetic automation owner' }).click();
    await expect(confirm(page).getByRole('button', { name: 'Revoke account', exact: true })).toBeDisabled();
    await confirm(page).getByRole('button', { name: 'Cancel', exact: true }).click(); expect(mutations).toHaveLength(1);
    await row.getByRole('button', { name: 'Revoke Synthetic automation owner' }).click();
    await confirm(page).getByRole('textbox').fill('wrong');
    await expect(confirm(page).getByRole('button', { name: 'Revoke account', exact: true })).toBeDisabled();
    await confirm(page).getByRole('textbox').fill('Synthetic automation owner');
    await confirm(page).getByRole('button', { name: 'Revoke account', exact: true }).click();
    await expect(row).toContainText('Revoked');
    expect(mutations).toEqual([`/v1/service-accounts/${created.id}/rotate`, `/v1/service-accounts/${created.id}/revoke`]);
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('tab', { name: 'Access', exact: true }).click();
    await receipt(testInfo, 'handleCreateServiceAccount', 'reload', async () => {
      await expect(page.getByRole('region', { name: /New service account secret|New secret for/ })).toHaveCount(0);
      await expect(page.locator('tbody tr').filter({ hasText: 'Synthetic automation owner' })).toContainText('Revoked');
      expect(await page.locator('#root').innerText()).not.toContain(created.secret);
      expect(await page.locator('#root').innerText()).not.toContain(rotated.secret);
      return ['Reload keeps scoped revoked account metadata but never restores either one-time automation secret'];
    });
  });

  test('vault required inputs, store/rotate review cancel, encrypted success and secret-free reload', async ({ page }, testInfo) => {
    await openSettings(page, 'Security');
    const panel = page.locator('#settings-sections-panel-security');
    const create = panel.locator('form').filter({ has: page.getByRole('button', { name: 'Store secret', exact: true }) });
    const rotate = panel.locator('form').filter({ has: page.getByRole('button', { name: 'Rotate secret', exact: true }) });
    const writes = [];
    page.on('request', (request) => { if (request.method() === 'POST' && /\/v1\/secrets(?:\/[^/]+\/rotate)?$/.test(request.url())) writes.push({ path: new URL(request.url()).pathname, body: request.postDataJSON() }); });
    await create.getByRole('button', { name: 'Store secret', exact: true }).click();
    expect(writes).toEqual([]); expect(await create.getByLabel('Name', { exact: true }).evaluate((input) => input.validity.valueMissing)).toBe(true);
    await create.getByLabel('Name', { exact: true }).fill('Synthetic vault credential');
    await create.getByLabel(/^Credential value/).fill('synthetic-local-vault-never-valid-provider');
    await create.getByRole('button', { name: 'Store secret', exact: true }).click();
    await confirm(page).getByRole('button', { name: 'Cancel', exact: true }).click();
    await receipt(testInfo, 'handleCreateVaultSecret', 'cancel', async () => {
      expect(writes).toEqual([]); await expect(create.getByLabel(/^Credential value/)).toHaveValue('synthetic-local-vault-never-valid-provider');
      return ['Vault review cancel retains typed local draft and creates zero encrypted secrets'];
    });
    await create.getByRole('button', { name: 'Store secret', exact: true }).click();
    const acceptedResponse = page.waitForResponse((response) => /\/v1\/secrets$/.test(response.url()) && response.request().method() === 'POST' && response.status() === 201);
    await confirm(page).getByRole('button', { name: 'Store secret', exact: true }).click();
    const accepted = await (await acceptedResponse).json();
    await receipt(testInfo, 'handleCreateVaultSecret', 'success', async () => {
      await expect(create.getByLabel(/^Credential value/)).toHaveValue('');
      const stored = getStore().encryptedSecrets.find((secret) => secret.id === accepted.secret.id); expect(stored.envelope.ciphertext).toBeTruthy();
      expect(JSON.stringify(accepted)).not.toContain('synthetic-local-vault-never-valid-provider');
      expect(writes).toHaveLength(1);
      return ['Exactly one vault write stores encrypted envelope; response/list metadata redacted and local plaintext cleared'];
    });
    await rotate.getByRole('combobox', { name: /^Secret/ }).selectOption(accepted.secret.id);
    await rotate.getByLabel('Replacement credential', { exact: true }).fill('synthetic-local-rotated-vault-never-valid-provider');
    await rotate.getByRole('button', { name: 'Rotate secret', exact: true }).click();
    await confirm(page).getByRole('button', { name: 'Cancel', exact: true }).click(); expect(writes).toHaveLength(1);
    await rotate.getByRole('button', { name: 'Rotate secret', exact: true }).click();
    await confirm(page).getByRole('button', { name: 'Rotate secret', exact: true }).click();
    await expect.poll(() => getStore().encryptedSecrets.find((secret) => secret.id === accepted.secret.id)?.rotation).toBe(1);
    expect(writes).toHaveLength(2);
    await page.getByRole('tab', { name: 'Access', exact: true }).click();
    await page.getByRole('tab', { name: 'Security', exact: true }).click();
    await expect(create.getByLabel(/^Credential value/)).toHaveValue('');
    await expect(rotate.getByLabel('Replacement credential', { exact: true })).toHaveValue('');
    await page.reload({ waitUntil: 'networkidle' });
    await receipt(testInfo, 'handleCreateVaultSecret', 'reload', async () => {
      await page.getByRole('tab', { name: 'Security', exact: true }).click();
      await expect(page.locator('tbody tr').filter({ hasText: 'Synthetic vault credential' })).toHaveCount(1);
      expect(await page.locator('#root').innerText()).not.toContain('synthetic-local-vault-never-valid-provider');
      expect(await page.locator('#root').innerText()).not.toContain('synthetic-local-rotated-vault-never-valid-provider');
      expect(writes).toHaveLength(2);
      return ['Tab leave and reload keep vault metadata but no create/rotate plaintext and no duplicate mutations'];
    });
  });
});
