/**
 * Guards the AWS deploy env so a secret cannot silently go missing or land in git.
 *
 * The VM reads ops/aws/.env (not committed). env.example is the contract: every
 * required key must be named there, none of the values may be a real secret, and
 * production role mapping must stay complete. The GitHub workflow only SSHes;
 * it must not inline host/key material.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { ROLES } from '../../src/contracts/roles.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ENV_EXAMPLE = 'ops/aws/env.example';
const COMPOSE_PATH = 'ops/aws/docker-compose.yml';
const WORKFLOW_PATH = '.github/workflows/deploy-aws.yml';
const FIXTURE_KEY = 'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON';

const read = (relative) => readFileSync(path.join(repoRoot, relative), 'utf8');

function envExampleEntries(text) {
  const entries = new Map();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    entries.set(line.slice(0, eq), line.slice(eq + 1));
  }
  return entries;
}

describe('aws deploy env contract', () => {
  const example = envExampleEntries(read(ENV_EXAMPLE));
  const exampleText = read(ENV_EXAMPLE);
  const workflow = read(WORKFLOW_PATH);
  const compose = read(COMPOSE_PATH);

  it('names every required runtime key in env.example', () => {
    const required = [
      'NODE_ENV',
      'PORT',
      'POSTGRES_PASSWORD',
      'ASTRANULL_PUBLIC_BASE_URL',
      'ASTRANULL_PERSISTENCE_MODE',
      'ASTRANULL_DEPLOYMENT_PROFILE',
      'ASTRANULL_BUNDLED_STAGING_OIDC',
      'ASTRANULL_AUTH_MODE',
      'ASTRANULL_OIDC_AUDIENCE',
      'ASTRANULL_OIDC_ROLE_MAP',
      'ASTRANULL_PUBLIC_LOGIN_URL',
      'ASTRANULL_PROBE_MODE',
      'ASTRANULL_HIGH_SCALE_ADAPTER_MODE',
      'ASTRANULL_AGENT_IDENTITY_MODE',
      'ASTRANULL_SECRET_ENCRYPTION_KEY',
      'ASTRANULL_PROBE_WORKER_SECRET',
      FIXTURE_KEY,
    ];
    const missing = required.filter((key) => !example.has(key));
    assert.deepEqual(missing, [], `${ENV_EXAMPLE} is missing ${missing.join(', ')}`);
  });

  it('pins production-like auth and persistence defaults', () => {
    assert.equal(example.get('NODE_ENV'), 'production');
    assert.equal(example.get('ASTRANULL_PERSISTENCE_MODE'), 'postgres');
    assert.equal(example.get('ASTRANULL_AUTH_MODE'), 'oidc-jwt');
    assert.equal(example.get('ASTRANULL_DEPLOYMENT_PROFILE'), 'hosted-staging');
    assert.equal(example.get('ASTRANULL_PUBLIC_BASE_URL'), 'https://astranull.site');
  });

  it('maps every platform role, because production resolves roles only through the map', () => {
    const raw = example.get('ASTRANULL_OIDC_ROLE_MAP');
    assert.ok(raw, `${ENV_EXAMPLE} must set ASTRANULL_OIDC_ROLE_MAP`);
    const mapped = new Set(
      raw.split(',').map((entry) => entry.split(':')[1]?.trim()).filter(Boolean),
    );
    const missing = ROLES.filter((role) => !mapped.has(role));
    assert.deepEqual(
      missing,
      [],
      `${ENV_EXAMPLE}: ASTRANULL_OIDC_ROLE_MAP omits ${missing.join(', ')}`,
    );
  });

  it('sets no staff role map, keeping staff role resolution fail-closed', () => {
    assert.equal(
      example.has('ASTRANULL_OIDC_STAFF_ROLE_MAP'),
      false,
      `${ENV_EXAMPLE} must NOT set ASTRANULL_OIDC_STAFF_ROLE_MAP`,
    );
  });

  it('does not inline private key material or usable secrets', () => {
    for (const relative of [ENV_EXAMPLE, COMPOSE_PATH, WORKFLOW_PATH, 'ops/aws/Dockerfile']) {
      const text = read(relative);
      assert.doesNotMatch(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, relative);
      assert.doesNotMatch(text, /AKIA[0-9A-Z]{16}/, relative);
    }
    assert.match(
      example.get(FIXTURE_KEY) ?? '',
      /^<|^placeholder|^paste/i,
      `${FIXTURE_KEY} must be a placeholder, not fixture JSON`,
    );
    assert.match(
      example.get('ASTRANULL_SECRET_ENCRYPTION_KEY') ?? '',
      /^</,
      'ASTRANULL_SECRET_ENCRYPTION_KEY must be a placeholder',
    );
  });

  it('keeps AWS Compose image-only and delegates the exact-archive build to deploy.sh', () => {
    const deploy = read('ops/aws/deploy.sh');
    const dockerfile = read('ops/aws/Dockerfile');

    assert.doesNotMatch(compose, /^\s+(?:build|context|dockerfile):/m);
    assert.match(deploy, /^build_control_plane_from_commit\(\) \{/m);
    assert.match(
      deploy,
      /git archive "\$commit" \\[\s\S]*\| timeout -k 30 480 docker build -f ops\/aws\/Dockerfile \\[\s\S]*-t "astranull-control-plane:\$commit" -/m,
    );
    assert.match(dockerfile, /^FROM\s+/m);
    assert.match(workflow, /secrets\.ASTRANULL_AWS_SSH_KEY/);
    assert.match(workflow, /secrets\.ASTRANULL_AWS_HOST/);
    assert.doesNotMatch(workflow, /AKIA[0-9A-Z]{16}/);
    assert.doesNotMatch(workflow, /-----BEGIN OPENSSH PRIVATE KEY-----/);
  });

  it('tells the operator not to commit .env', () => {
    assert.match(exampleText, /never commit/i);
  });
});
