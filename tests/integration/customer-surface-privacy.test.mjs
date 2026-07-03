import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { resetSignupRateLimitsForTests } from '../../src/services/signupIntake.mjs';

const STAFF_PATH_RE = /\/internal\/admin|staff-login|AstraNull staff\?|Internal management sign-in/i;

let baseUrl;
let server;

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  resetSignupRateLimitsForTests();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('customer surface privacy (no staff login exposure)', () => {
  const customerPaths = ['/', '/login', '/signup', '/app'];

  for (const path of customerPaths) {
    it(`does not expose staff routes on ${path}`, async () => {
      const res = await request(baseUrl, 'GET', path);
      assert.equal(res.status, 200);
      assert.doesNotMatch(res.text, STAFF_PATH_RE, `${path} must not link to staff surfaces`);
    });
  }

  it('does not publish staff paths in public site-config', async () => {
    const config = await request(baseUrl, 'GET', '/v1/public/site-config');
    assert.equal(config.status, 200);
    assert.equal(config.json.staff_login_path, undefined);
    assert.equal(config.json.internal_admin_path, undefined);
    const serialized = JSON.stringify(config.json);
    assert.doesNotMatch(serialized, /\/internal\/admin/);
  });

  it('still serves staff login only via direct URL (unlinked)', async () => {
    const staffLogin = await request(baseUrl, 'GET', '/internal/admin/login');
    assert.equal(staffLogin.status, 200);
    assert.match(staffLogin.text, /Staff sign-in/);
    assert.match(staffLogin.text, /noindex/i);
  });
});