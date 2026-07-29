import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exchangeGuardianBotDastSession } from '../../src/services/guardianbotDastSession.mjs';

const TOKEN = 'exchange-token-with-at-least-32-characters';
const ENV = {
  ASTRANULL_BUNDLED_STAGING_OIDC: '1',
  ASTRANULL_PUBLIC_BASE_URL: 'https://astranull-staging.example.com',
  ASTRANULL_OIDC_ISSUER: 'https://astranull-staging.example.com/staging-oidc',
  ASTRANULL_OIDC_JWKS_URL: 'https://astranull-staging.example.com/.well-known/jwks.json',
  GUARDIANBOT_DAST_EXCHANGE_TOKEN: TOKEN,
  GUARDIANBOT_DAST_REPOSITORY: 'geekyshubham/astranull',
  GUARDIANBOT_DAST_REPOSITORY_ID: '1287322655',
  GUARDIANBOT_DAST_DEPLOYMENT_ENVIRONMENT: 'staging',
};

function body(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    purpose: 'guardianbot-dast',
    repository: 'geekyshubham/astranull',
    repositoryId: 1287322655,
    runId: 123,
    runAttempt: 1,
    headSha: 'a'.repeat(40),
    deploymentEnvironment: 'staging',
    deployedDigest: `sha256:${'b'.repeat(64)}`,
    ttlSeconds: 600,
    ...overrides,
  };
}

test('GuardianBot DAST exchange is hidden when not configured', () => {
  const result = exchangeGuardianBotDastSession({
    authorization: `Bearer ${TOKEN}`,
    body: body(),
    env: {},
  });
  assert.equal(result.status, 404);
});

test('GuardianBot DAST exchange rejects a wrong secret', () => {
  const result = exchangeGuardianBotDastSession({
    authorization: 'Bearer wrong',
    body: body(),
    env: ENV,
  });
  assert.deepEqual(result, { status: 401, body: { error: 'unauthorized' } });
});

test('GuardianBot DAST exchange rejects unbound deployment metadata', () => {
  const result = exchangeGuardianBotDastSession({
    authorization: `Bearer ${TOKEN}`,
    body: body({ deployedDigest: 'sha256:bad' }),
    env: ENV,
  });
  assert.deepEqual(result, { status: 400, body: { error: 'invalid_request' } });
});

test('GuardianBot DAST exchange mints a short-lived viewer bearer', () => {
  const now = Date.parse('2026-07-29T00:00:00.000Z');
  const result = exchangeGuardianBotDastSession({
    authorization: `Bearer ${TOKEN}`,
    body: body(),
    env: ENV,
    now,
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.schemaVersion, '1.0.0');
  assert.match(result.body.credential, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  assert.equal(result.body.expiresAt, '2026-07-29T00:10:00.000Z');

  const claims = JSON.parse(
    Buffer.from(result.body.credential.split(' ')[1].split('.')[1], 'base64url').toString('utf8'),
  );
  assert.equal(claims.role, 'viewer');
  assert.equal(claims.sub, 'guardianbot-dast');
  assert.equal(claims.tenant_id, 'ten_demo');
  assert.equal(claims.exp, Math.floor(now / 1000) + 600);
});
