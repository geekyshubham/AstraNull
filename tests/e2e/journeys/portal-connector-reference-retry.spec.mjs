import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { getStore } from '../../../src/store.mjs';
import { buildPortalActionInventory, assertSourcePortalAction } from '../../helpers/portal-action-coverage.mjs';
import { startPortalPlaywrightServer, stopPortalPlaywrightServer, getPortalPlaywrightBaseUrl } from '../../helpers/portal-playwright-server.mjs';
import { gotoPortalRoute, injectPortalDevHeadersSession } from '../../helpers/portal-playwright-session.mjs';

const SYNTHETIC_CREDENTIAL = 'synthetic-local-connector-reference-retry-never-valid-at-provider';
const CONNECTOR_NAME = 'Synthetic reference retry connector';
const inventory = buildPortalActionInventory();
const form = (page) => page.locator('dialog.form-modal[open]').filter({ hasText: 'Connect Cloudflare read-only' });

async function openConnectorForm(page) {
  await gotoPortalRoute(page, 'integrations', getPortalPlaywrightBaseUrl());
  await page.getByRole('button', { name: 'Add provider', exact: true }).click();
  const provider = page.locator('dialog.form-modal[open]');
  await provider.getByRole('button', { name: 'Continue to connect', exact: true }).click();
  await expect(form(page)).toBeVisible();
}

async function receipt(testInfo, state, assertBehavior) {
  return assertSourcePortalAction(testInfo, inventory, { owner: 'IntegrationPage', handler: 'handleCreateConnector', kind: 'form-keyboard' }, state, assertBehavior, { route: 'integrations' });
}

test.describe('existing Cloudflare connector credential custody and reference-only recovery', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ liveSource: true, env: { ASTRANULL_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64') } });
  });
  test.afterAll(async () => { await stopPortalPlaywrightServer(); });

  test('validate-only → exactly one vault write → connector failure → same-secret reference-only retry, no poll and accepted reload', async ({ page }, testInfo) => {
    await injectPortalDevHeadersSession(page);
    const requests = [];
    const vaultResponses = [];
    let createAttempts = 0;
    let releaseCreateFailure;
    const heldFailure = new Promise((resolve) => { releaseCreateFailure = resolve; });
    const polls = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (request.method() === 'POST' && ['/v1/connectors', '/v1/secrets'].includes(url.pathname)) requests.push({ path: url.pathname, body: request.postDataJSON() });
      if (/\/v1\/connectors\/[^/]+\/poll$/.test(url.pathname)) polls.push(request.url());
    });
    page.on('response', async (response) => {
      if (new URL(response.url()).pathname === '/v1/secrets' && response.request().method() === 'POST' && response.status() === 201) vaultResponses.push(await response.json());
    });
    await page.route('**/v1/connectors', async (route) => {
      const request = route.request();
      if (request.method() !== 'POST' || request.postDataJSON().validate_only) return route.continue();
      createAttempts += 1;
      if (createAttempts === 1) {
        await heldFailure;
        return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'synthetic_connector_failure', message: 'Synthetic connector admission outage' }) });
      }
      return route.continue();
    });
    const secretsBefore = getStore().encryptedSecrets.length;
    const connectorsBefore = getStore().wafConnectors.length;
    await openConnectorForm(page);
    const modal = form(page);
    await modal.getByLabel('Connector name', { exact: true }).fill(CONNECTOR_NAME);
    await modal.getByLabel('New read-only credential', { exact: true }).fill(SYNTHETIC_CREDENTIAL);
    await modal.getByRole('button', { name: 'Create read-only connector', exact: true }).click();
    const confirm = page.locator('dialog.modal-confirm:not(.form-modal)[open]');
    await expect(confirm).toContainText('Store provider credential');
    expect(requests).toEqual([]);
    await confirm.getByRole('button', { name: 'Store and create', exact: true }).click();
    try {
      await receipt(testInfo, 'busy', async () => {
        await expect.poll(() => vaultResponses.length).toBe(1);
        await expect.poll(() => createAttempts).toBe(1);
        await expect(modal.locator('form')).toHaveAttribute('aria-busy', 'true');
        await expect(modal.getByRole('button', { name: /Create read-only connector|Working/ })).toBeDisabled();
        await expect(modal.getByLabel('New read-only credential', { exact: true })).toBeDisabled();
        await modal.getByRole('button', { name: /Create read-only connector|Working/ }).press('Enter');
        expect(requests.filter((request) => request.path === '/v1/secrets')).toHaveLength(1);
        expect(createAttempts).toBe(1);
        return ['Real validate_only and vault operations complete before delayed connector admission; busy form and disabled credential/submit prevent duplicate vault/create writes'];
      });
    } finally { releaseCreateFailure(); }
    const secretId = vaultResponses[0].secret.id;
    await expect(modal.getByRole('alert')).toContainText(`vault secret ${secretId}`);
    await expect(modal.getByRole('alert')).toContainText('existing secret reference');
    expect(requests.map((request) => request.path)).toEqual(['/v1/connectors', '/v1/secrets', '/v1/connectors']);
    expect(requests[0].body.validate_only).toBe(true);
    expect(requests[1].body.plaintext).toBe(SYNTHETIC_CREDENTIAL);
    expect(requests[2].body.secret_id).toBe(secretId);
    expect(getStore().encryptedSecrets).toHaveLength(secretsBefore + 1);
    expect(getStore().wafConnectors).toHaveLength(connectorsBefore);
    await modal.getByLabel('New read-only credential', { exact: true }).fill('');
    await modal.getByLabel('Or existing vault secret ref', { exact: true }).fill(secretId);
    const acceptedResponse = page.waitForResponse((response) => new URL(response.url()).pathname === '/v1/connectors' && response.request().method() === 'POST' && response.status() === 201 && !response.request().postDataJSON().validate_only);
    await modal.getByRole('button', { name: 'Create read-only connector', exact: true }).click();
    const accepted = await (await acceptedResponse).json();
    await receipt(testInfo, 'error-retry', async () => {
      await expect(modal).toBeHidden();
      expect(requests.filter((request) => request.path === '/v1/secrets')).toHaveLength(1);
      expect(requests.filter((request) => request.path === '/v1/connectors' && request.body.validate_only)).toHaveLength(1);
      expect(requests[3].body).toEqual(requests[2].body);
      expect(accepted.connector.secret_id).toBe(secretId);
      expect(getStore().encryptedSecrets).toHaveLength(secretsBefore + 1);
      expect(getStore().wafConnectors.filter((connector) => connector.name === CONNECTOR_NAME)).toHaveLength(1);
      for (const request of requests.filter((request) => request.path === '/v1/connectors')) {
        expect(JSON.stringify(request.body)).not.toContain(SYNTHETIC_CREDENTIAL);
        expect(request.body).not.toHaveProperty('plaintext'); expect(request.body.config).not.toHaveProperty('token');
      }
      expect(polls).toEqual([]);
      expect(JSON.stringify(getStore().auditLog)).not.toContain(SYNTHETIC_CREDENTIAL);
      return ['Reference-only retry reuses exact secret_id and connector payload; exactly one validate-only/vault write, no plaintext in connector or audit, no poll and one accepted connector'];
    });
    await page.reload({ waitUntil: 'networkidle' });
    await receipt(testInfo, 'reload', async () => {
      await expect(page.getByText(CONNECTOR_NAME, { exact: true })).toBeVisible();
      expect(getStore().wafConnectors.find((connector) => connector.id === accepted.connector.id)?.secret_id).toBe(secretId);
      expect(requests.filter((request) => request.path === '/v1/secrets')).toHaveLength(1);
      expect(createAttempts).toBe(2); expect(polls).toEqual([]);
      return ['Reload renders accepted existing-provider connector backed by the original encrypted secret, no additional creation/poll'];
    });
  });

  test('invalid credential/reference combination and review cancel write nothing and preserve the local draft', async ({ page }, testInfo) => {
    await injectPortalDevHeadersSession(page);
    const writes = [];
    page.on('request', (request) => { if (request.method() === 'POST' && /\/v1\/(secrets|connectors)$/.test(request.url())) writes.push(request.url()); });
    await openConnectorForm(page);
    const modal = form(page);
    await modal.getByLabel('Connector name', { exact: true }).fill('Cancelled synthetic connector');
    await modal.getByLabel('New read-only credential', { exact: true }).fill(SYNTHETIC_CREDENTIAL);
    await modal.getByLabel('Or existing vault secret ref', { exact: true }).fill('secret_synthetic_existing_reference');
    await modal.getByRole('button', { name: 'Create read-only connector', exact: true }).click();
    await receipt(testInfo, 'invalid', async () => {
      await expect(modal.getByRole('alert')).toContainText('Choose either a new credential or an existing secret reference, not both.');
      expect(writes).toEqual([]);
      return ['Mutually exclusive credential/reference validation denies submission before validate-only/vault/connector writes'];
    });
    await modal.getByLabel('Or existing vault secret ref', { exact: true }).fill('');
    await modal.getByRole('button', { name: 'Create read-only connector', exact: true }).click();
    await page.locator('dialog.modal-confirm:not(.form-modal)[open]').getByRole('button', { name: 'Cancel', exact: true }).click();
    await receipt(testInfo, 'cancel', async () => {
      await expect(modal.getByLabel('Connector name', { exact: true })).toHaveValue('Cancelled synthetic connector');
      await expect(modal.getByLabel('New read-only credential', { exact: true })).toHaveValue(SYNTHETIC_CREDENTIAL);
      expect(writes).toEqual([]);
      return ['Credential review cancellation retains local setup draft and produces zero writes'];
    });
    await modal.getByRole('button', { name: 'Cancel', exact: true }).click();
    await modal.getByRole('button', { name: 'Discard', exact: true }).click();
    await expect(modal).toBeHidden(); expect(writes).toEqual([]);
  });
});
