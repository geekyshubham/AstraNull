import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../..');
const CRONJOB_DIR = path.join(ROOT, 'ops', 'kubernetes', 'cronjobs');
const CASES = [
  {
    file: 'notification-retry-scheduler.yaml',
    env: [
      'NODE_ENV',
      'ASTRANULL_PERSISTENCE_MODE',
      'ASTRANULL_ENFORCE_DATABASE_ROLE',
      'ASTRANULL_NOTIFICATION_DELIVERY_MODE',
      'ASTRANULL_DATABASE_URL',
      'ASTRANULL_PG_SSL_CA',
    ],
    secretKeys: ['ASTRANULL_DATABASE_URL', 'ASTRANULL_PG_SSL_CA'],
  },
  {
    file: 'waf-drift-runner.yaml',
    env: [
      'NODE_ENV',
      'ASTRANULL_PERSISTENCE_MODE',
      'ASTRANULL_ENFORCE_DATABASE_ROLE',
      'ASTRANULL_WAF_POSTURE_ENABLED',
      'ASTRANULL_DATABASE_URL',
      'ASTRANULL_PG_SSL_CA',
    ],
    secretKeys: ['ASTRANULL_DATABASE_URL', 'ASTRANULL_PG_SSL_CA'],
  },
  {
    file: 'waf-orchestrator-runner.yaml',
    env: [
      'NODE_ENV',
      'ASTRANULL_PERSISTENCE_MODE',
      'ASTRANULL_ENFORCE_DATABASE_ROLE',
      'ASTRANULL_PROBE_MODE',
      'ASTRANULL_DATABASE_URL',
      'ASTRANULL_PG_SSL_CA',
      'ASTRANULL_PROBE_WORKER_SECRET',
    ],
    secretKeys: [
      'ASTRANULL_DATABASE_URL',
      'ASTRANULL_PG_SSL_CA',
      'ASTRANULL_PROBE_WORKER_SECRET',
    ],
  },
];

function envNames(source) {
  return [...source.matchAll(/^\s+- name: (NODE_ENV|ASTRANULL_[A-Z0-9_]+)\s*$/gm)]
    .map((match) => match[1]);
}

function secretKeys(source) {
  return [...source.matchAll(/^\s+key: (ASTRANULL_[A-Z0-9_]+)\s*$/gm)]
    .map((match) => match[1]);
}

const FORBIDDEN = [
  'ASTRANULL_SECRET_ENCRYPTION_KEY',
  'ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY',
  'ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY',
  'ASTRANULL_OIDC_ISSUER',
  'ASTRANULL_OIDC_AUDIENCE',
  'ASTRANULL_OIDC_JWKS_URL',
  'ASTRANULL_SESSION_SECRET',
  'ASTRANULL_EVIDENCE_SIGNING_KEY',
  'ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON',
  'ASTRANULL_SMTP_PASSWORD',
  'ASTRANULL_POSTGRES_AUTO_MIGRATE',
  'ASTRANULL_PG_SSL_REJECT_UNAUTHORIZED',
];

describe('Kubernetes auxiliary CronJob least privilege', () => {
  for (const spec of CASES) {
    it(`${spec.file} projects only its required configuration`, () => {
      const source = readFileSync(path.join(CRONJOB_DIR, spec.file), 'utf8');
      assert.match(source, /apiVersion: batch\/v1/);
      assert.match(source, /activeDeadlineSeconds: 180/);
      assert.match(source, /automountServiceAccountToken: false/);
      assert.match(source, /serviceAccountName: astranull-worker/);
      assert.equal(source.includes('envFrom:'), false);
      assert.deepEqual(envNames(source), spec.env);
      assert.deepEqual(secretKeys(source), spec.secretKeys);
      assert.match(source, /name: astranull-worker-env/);
      assert.match(
        source,
        /configMap:\n\s+name: astranull-worker-tenant-ids\n\s+items:\n\s+- key: tenant-ids\.json\n\s+path: tenant-ids\.json/,
      );
      for (const name of FORBIDDEN) assert.equal(source.includes(name), false, name);
    });
  }

  it('binds scheduled Pods only to explicit zero-permission RBAC', () => {
    const rbac = readFileSync(path.join(CRONJOB_DIR, 'worker-rbac.yaml'), 'utf8');
    assert.match(rbac, /kind: ServiceAccount[\s\S]*name: astranull-worker[\s\S]*automountServiceAccountToken: false/);
    assert.match(rbac, /kind: Role[\s\S]*name: astranull-worker-zero-permission[\s\S]*rules: \[\]/);
    assert.match(rbac, /kind: RoleBinding[\s\S]*kind: ServiceAccount[\s\S]*name: astranull-worker/);
    assert.doesNotMatch(rbac, /verbs:\s*\[|resources:\s*\[/);
  });

  it('keeps notification delivery metadata-only and orchestrator probes signed', () => {
    const notification = readFileSync(
      path.join(CRONJOB_DIR, 'notification-retry-scheduler.yaml'),
      'utf8',
    );
    assert.match(
      notification,
      /name: ASTRANULL_NOTIFICATION_DELIVERY_MODE\n\s+value: metadata_only/,
    );
    const orchestrator = readFileSync(
      path.join(CRONJOB_DIR, 'waf-orchestrator-runner.yaml'),
      'utf8',
    );
    assert.match(orchestrator, /name: ASTRANULL_PROBE_MODE\n\s+value: signed-worker/);
  });
});
