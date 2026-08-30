import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACCESSIBILITY_RUNNER_IDENTITY,
  ACCESSIBILITY_RUNNER_PASSWORD_ENV,
  loginCustomer,
} from '../../scripts/run-live-ui-accessibility-matrix.mjs';

function mockLoginPage(config, {
  loginUrl = 'https://staging.astranull.invalid/login',
  loginResponseStatus = 200,
} = {}) {
  const events = [];
  let currentUrl = 'about:blank';
  let loginRouteHandler;
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
    async goto(url) {
      events.push(`goto:${url}`);
      currentUrl = loginUrl;
    },
    url() { return currentUrl; },
    async route(pattern, handler) {
      events.push(`route:${pattern}`);
      loginRouteHandler = handler;
    },
    async unroute(pattern, handler) {
      assert.equal(handler, loginRouteHandler);
      events.push(`unroute:${pattern}`);
      loginRouteHandler = undefined;
    },
    locator(selector) {
      if (selector === '#login-user-id') {
        return {
          async fill(value) { events.push(`fill:${value}`); },
        };
      }
      if (selector === 'details.auth-bypass > summary') {
        return {
          async click() { throw new Error('credentialless bypass must not be selected'); },
        };
      }
      if (selector === '#login-password') {
        return {
          async fill(value) { events.push(`password:${value}`); },
        };
      }
      throw new Error(`Unexpected locator: ${selector}`);
    },
    getByRole(role, options) {
      assert.equal(role, 'button');
      assert.deepEqual(options, { name: 'Continue to portal', exact: true });
      return {
        async click() {
          if (loginRouteHandler) {
            await loginRouteHandler({
              async fetch(options) {
                assert.deepEqual(options, { maxRedirects: 0 });
                events.push(`login-fetch:${loginResponseStatus}`);
                return { status: () => loginResponseStatus };
              },
              async fulfill(options) {
                events.push(`login-fulfill:${options.status ?? options.response?.status()}`);
              },
              async abort(reason) { events.push(`login-abort:${reason}`); },
            });
          }
          events.push('click:continue');
        },
      };
    },
    async waitForURL(predicate) {
      if (loginResponseStatus >= 300 && loginResponseStatus < 400) {
        return new Promise(() => {});
      }
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
  assert.ok(events.includes('reached:/app'));
  assert.equal(events.at(-1), 'main:visible');
});

test('loginCustomer uses the injected password and never opens the advertised staging bypass', async () => {
  const { events, page } = mockLoginPage({
    auth_mode: 'oidc-jwt',
    bundled_staging_login_enabled: true,
    password_login_enabled: true,
  });
  const injected = 'test-only-credential';

  await loginCustomer(page, 'https://staging.astranull.invalid', {
    [ACCESSIBILITY_RUNNER_PASSWORD_ENV]: injected,
  });

  assert.ok(events.indexOf(`fill:${ACCESSIBILITY_RUNNER_IDENTITY}`) < events.indexOf(`password:${injected}`));
  assert.ok(events.indexOf(`password:${injected}`) < events.indexOf('click:continue'));
  assert.ok(events.includes('reached:/app'));
});

test('loginCustomer fails closed before navigation when the runner password is absent', async () => {
  for (const config of [
    {
      auth_mode: 'oidc-jwt',
      bundled_staging_login_enabled: true,
      password_login_enabled: true,
    },
    {
      auth_mode: 'signed-session',
      bundled_staging_login_enabled: false,
      password_login_enabled: true,
    },
  ]) {
    const { events, page } = mockLoginPage(config);
    await assert.rejects(
      loginCustomer(page, 'https://staging.astranull.invalid', {}),
      new RegExp(`requires ${ACCESSIBILITY_RUNNER_PASSWORD_ENV}.*refusing credentialless login`),
    );
    assert.deepEqual(events, ['config:https://staging.astranull.invalid/v1/public/site-config']);
  }
});

test('loginCustomer rejects an enterprise IdP before navigation even when a password is injected', async () => {
  const { events, page } = mockLoginPage({
    auth_mode: 'oidc-jwt',
    bundled_staging_login_enabled: false,
    password_login_enabled: true,
  });

  await assert.rejects(
    loginCustomer(page, 'https://enterprise.astranull.invalid', {
      [ACCESSIBILITY_RUNNER_PASSWORD_ENV]: 'test-only-credential',
    }),
    /cannot use password login.*enterprise IdP login requires a separate credentialed harness/,
  );
  assert.deepEqual(events, ['config:https://enterprise.astranull.invalid/v1/public/site-config']);
});

test('loginCustomer refuses non-loopback HTTP before discovery or navigation', async () => {
  const { events, page } = mockLoginPage({
    auth_mode: 'oidc-jwt',
    bundled_staging_login_enabled: true,
    password_login_enabled: true,
  });

  await assert.rejects(
    loginCustomer(page, 'http://staging.astranull.invalid', {
      [ACCESSIBILITY_RUNNER_PASSWORD_ENV]: 'test-only-credential',
    }),
    /sends credentials only to HTTPS origins/,
  );
  assert.deepEqual(events, []);
});

test('loginCustomer refuses a cross-origin login redirect before filling credentials', async () => {
  const { events, page } = mockLoginPage(
    {
      auth_mode: 'oidc-jwt',
      bundled_staging_login_enabled: true,
      password_login_enabled: true,
    },
    { loginUrl: 'https://attacker.invalid/login' },
  );

  await assert.rejects(
    loginCustomer(page, 'https://staging.astranull.invalid', {
      [ACCESSIBILITY_RUNNER_PASSWORD_ENV]: 'test-only-credential',
    }),
    /navigation left the configured origin; refusing to send credentials/,
  );
  assert.equal(events.some((event) => event.startsWith('fill:')), false);
  assert.equal(events.some((event) => event.startsWith('password:')), false);
});


test('loginCustomer blocks redirects from the credential-bearing login POST', async () => {
  const { events, page } = mockLoginPage(
    {
      auth_mode: 'oidc-jwt',
      bundled_staging_login_enabled: true,
      password_login_enabled: true,
    },
    { loginResponseStatus: 307 },
  );

  await assert.rejects(
    loginCustomer(page, 'https://staging.astranull.invalid', {
      [ACCESSIBILITY_RUNNER_PASSWORD_ENV]: 'test-only-credential',
    }),
    /refused a redirect from the credential-bearing login endpoint/,
  );
  assert.ok(events.includes('login-fetch:307'));
  assert.ok(events.includes('login-fulfill:502'));
  assert.equal(events.includes('main:visible'), false);
});
