import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACCESSIBILITY_RUNNER_IDENTITY,
  loginCustomer,
} from '../../scripts/run-live-ui-accessibility-matrix.mjs';

function mockLoginPage(config) {
  const events = [];
  const page = {
    request: {
      async get(url) {
        events.push(`config:${url}`);
        return {
          ok: () => true,
          async json() { return config; },
        };
      },
    },
    async goto(url) { events.push(`goto:${url}`); },
    locator(selector) {
      if (selector === '#login-user-id') {
        return {
          async fill(value) { events.push(`fill:${value}`); },
        };
      }
      if (selector === 'details.auth-bypass > summary') {
        return {
          async click() { events.push('click:staging-bypass'); },
        };
      }
      if (selector === '#login-password') {
        return {
          async waitFor({ state }) { events.push(`password:${state}`); },
        };
      }
      throw new Error(`Unexpected locator: ${selector}`);
    },
    getByRole(role, options) {
      assert.equal(role, 'button');
      assert.deepEqual(options, { name: 'Continue to portal', exact: true });
      return {
        async click() { events.push('click:continue'); },
      };
    },
    async waitForURL(predicate) {
      assert.equal(predicate(new URL('https://staging.astranull.invalid/app')), true);
      events.push('reached:/app');
    },
    async waitForSelector(selector, options) {
      assert.equal(selector, 'main.main');
      assert.deepEqual(options, { state: 'visible', timeout: 30000 });
      events.push('main:visible');
    },
  };
  return { events, page };
}

test('loginCustomer fills the deterministic validation identity before submit and reaches /app', async () => {
  const { events, page } = mockLoginPage({
    auth_mode: 'dev-headers',
    bundled_staging_login_enabled: false,
    password_login_enabled: false,
  });

  await loginCustomer(page, 'https://staging.astranull.invalid');

  const fill = `fill:${ACCESSIBILITY_RUNNER_IDENTITY}`;
  assert.equal(ACCESSIBILITY_RUNNER_IDENTITY, 'accessibility-runner@astranull.invalid');
  assert.ok(events.indexOf(fill) < events.indexOf('click:continue'));
  assert.deepEqual(events.slice(-3), ['click:continue', 'reached:/app', 'main:visible']);
});

test('loginCustomer selects an advertised bundled staging bypass instead of the password lane', async () => {
  const { events, page } = mockLoginPage({
    auth_mode: 'oidc-jwt',
    bundled_staging_login_enabled: true,
    password_login_enabled: true,
  });

  await loginCustomer(page, 'https://staging.astranull.invalid');

  assert.ok(events.indexOf('click:staging-bypass') < events.indexOf(`fill:${ACCESSIBILITY_RUNNER_IDENTITY}`));
  assert.ok(events.includes('password:detached'));
  assert.ok(events.includes('reached:/app'));
});

test('loginCustomer fails closed before navigation for enterprise IdP or password login', async () => {
  for (const authMode of ['oidc-jwt', 'signed-session']) {
    const { events, page } = mockLoginPage({
      auth_mode: authMode,
      bundled_staging_login_enabled: false,
      password_login_enabled: true,
    });

    await assert.rejects(
      loginCustomer(page, 'https://enterprise.astranull.invalid'),
      /refuses credentialless login.*Enterprise password and real IdP login require a credentialed harness/,
    );
    assert.deepEqual(events, ['config:https://enterprise.astranull.invalid/v1/public/site-config']);
  }
});
