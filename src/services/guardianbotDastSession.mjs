import { timingSafeEqual } from 'node:crypto';
import { mintBundledStagingOidcJwt } from '../lib/bundledStagingOidc.mjs';

const REQUEST_FIELDS = new Set([
  'schemaVersion',
  'purpose',
  'repository',
  'repositoryId',
  'runId',
  'runAttempt',
  'headSha',
  'deploymentEnvironment',
  'deployedDigest',
  'ttlSeconds',
]);

function exactSecretMatch(supplied, expected) {
  const left = Buffer.from(String(supplied ?? ''), 'utf8');
  const right = Buffer.from(String(expected ?? ''), 'utf8');
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right);
}

function invalidMetadata(body, env) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return true;
  const keys = Object.keys(body);
  if (keys.length !== REQUEST_FIELDS.size || keys.some((key) => !REQUEST_FIELDS.has(key))) {
    return true;
  }
  const repositoryId = Number(body.repositoryId);
  const runId = Number(body.runId);
  const runAttempt = Number(body.runAttempt);
  const ttlSeconds = Number(body.ttlSeconds);
  return (
    body.schemaVersion !== '1.0.0'
    || body.purpose !== 'guardianbot-dast'
    || String(body.repository ?? '').toLowerCase()
      !== String(env.GUARDIANBOT_DAST_REPOSITORY ?? '').toLowerCase()
    || !Number.isSafeInteger(repositoryId)
    || String(repositoryId) !== String(env.GUARDIANBOT_DAST_REPOSITORY_ID ?? '')
    || !Number.isSafeInteger(runId)
    || runId <= 0
    || !Number.isSafeInteger(runAttempt)
    || runAttempt <= 0
    || !Number.isSafeInteger(ttlSeconds)
    || ttlSeconds < 60
    || ttlSeconds > 900
    || String(body.deploymentEnvironment ?? '')
      !== String(env.GUARDIANBOT_DAST_DEPLOYMENT_ENVIRONMENT ?? 'staging')
    || !/^[a-f0-9]{40}$/i.test(String(body.headSha ?? ''))
    || !/^sha256:[a-f0-9]{64}$/i.test(String(body.deployedDigest ?? ''))
  );
}

/**
 * Exchange a control-plane-only authorization value for a short-lived,
 * read-only bundled-staging OIDC bearer.
 */
export function exchangeGuardianBotDastSession({ authorization, body, env = process.env, now = Date.now() }) {
  const expected = String(env.GUARDIANBOT_DAST_EXCHANGE_TOKEN ?? '').trim();
  const repository = String(env.GUARDIANBOT_DAST_REPOSITORY ?? '').trim();
  const repositoryId = String(env.GUARDIANBOT_DAST_REPOSITORY_ID ?? '').trim();
  if (!expected || !repository || !repositoryId || env.ASTRANULL_BUNDLED_STAGING_OIDC !== '1') {
    return { status: 404, body: { error: 'not_configured' } };
  }

  const match = /^Bearer ([^\s]+)$/.exec(String(authorization ?? ''));
  if (!match || !exactSecretMatch(match[1], expected)) {
    return { status: 401, body: { error: 'unauthorized' } };
  }
  if (invalidMetadata(body, env)) {
    return { status: 400, body: { error: 'invalid_request' } };
  }

  const ttlSeconds = Number(body.ttlSeconds);
  const expirySeconds = Math.floor(now / 1000) + ttlSeconds;
  const credential = mintBundledStagingOidcJwt(
    {
      role: 'viewer',
      userId: 'guardianbot-dast',
      tenantId: 'ten_demo',
      exp: expirySeconds,
    },
    env,
  );
  return {
    status: 200,
    body: {
      schemaVersion: '1.0.0',
      credential: `Bearer ${credential}`,
      expiresAt: new Date(expirySeconds * 1000).toISOString(),
    },
  };
}
