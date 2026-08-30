import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { validateAwsComposeSecretModel } from '../../scripts/validate-aws-compose-secrets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relative) => readFileSync(path.join(ROOT, relative), 'utf8');

describe('AWS release path hardening', () => {
  const workflow = read('.github/workflows/deploy-aws.yml');
  const ci = read('.github/workflows/ci.yml');
  const deploy = read('ops/aws/deploy.sh');
  const compose = read('ops/aws/docker-compose.yml');

  it('fetches, verifies, transfers, and executes deploy logic from the exact successful CI SHA', () => {
    assert.match(workflow, /workflow_run:[\s\S]*workflows: \["CI"\][\s\S]*branches: \["main"\]/m);
    assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
    assert.match(workflow, /github\.event\.workflow_run\.event == 'push'/);
    assert.match(workflow, /github\.event\.workflow_run\.head_repository\.full_name == github\.repository/);
    assert.match(workflow, /DEPLOY_SHA: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
    assert.doesNotMatch(workflow, /workflow_dispatch/);

    assert.match(workflow, /uses: actions\/checkout@[0-9a-f]{40}/);
    assert.match(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
    assert.match(workflow, /persist-credentials: false/);
    assert.match(workflow, /git rev-parse HEAD[\s\S]*DEPLOY_SHA/);
    assert.match(workflow, /git diff --exit-code -- ops\/aws\/deploy\.sh/);
    assert.match(workflow, /script_sha256=\$\(sha256sum ops\/aws\/deploy\.sh/);
    assert.match(workflow, /scp[\s\S]*ops\/aws\/deploy\.sh[\s\S]*remote_script/m);
    assert.match(workflow, /sha256sum -c -/);
    assert.match(workflow, /bash '\$remote_script' '\$DEPLOY_SHA'/);
    assert.doesNotMatch(workflow, /bash \/opt\/astranull\/ops\/aws\/deploy\.sh/);

    assert.match(workflow, /ASTRANULL_AWS_KNOWN_HOSTS/);
    assert.match(workflow, /StrictHostKeyChecking=yes/);
    assert.match(workflow, /timeout 1800 ssh/);
    assert.match(workflow, /ServerAliveInterval=30/);
    assert.match(workflow, /ServerAliveCountMax=3/);
    assert.match(workflow, /trap cleanup EXIT/);
    assert.match(workflow, /rm -f .*astranull-deploy/);
  });

  it('rejects stale or dirty releases and serializes bounded exact-SHA deploys', () => {
    assert.equal(statSync(path.join(ROOT, 'ops/aws/deploy.sh')).mode & 0o111, 0o111);
    assert.match(deploy, /flock -n 9/);
    assert.match(deploy, /git status --porcelain --untracked-files=all/);
    assert.match(deploy, /remote_main=\$\(git rev-parse origin\/main\)/);
    assert.match(deploy, /\[\[ "\$SHA" == "\$remote_main" \]\]/);
    assert.match(deploy, /timeout -k 10 60 git fetch/);
    assert.match(deploy, /compose_timeout 180 exec[\s\S]*pg_dump/m);
    assert.match(deploy, /postgres_cid=\$\(compose_timeout 30 ps -q postgres\)/);
    assert.doesNotMatch(deploy, /\$\(compose ps -q/);
    assert.match(deploy, /compose_timeout 90[\s\S]*postgres-backup\.mjs/m);
    assert.match(deploy, /timeout -k 30 480 docker build/);
    assert.match(deploy, /--wait --wait-timeout 240/);
  });

  it('uses target-SHA Compose for normal release phases and keeps current orchestration for rollback', () => {
    assert.match(deploy, /previous_compose=\$\(mktemp/);
    assert.match(deploy, /target_compose=\$\(mktemp/);
    assert.match(deploy, /git show "\$previous:\$COMPOSE_REPO_PATH" > "\$previous_compose"/);
    assert.match(deploy, /git show "\$SHA:\$COMPOSE_REPO_PATH" > "\$target_compose"/);

    const releaseBoundary = deploy.slice(deploy.lastIndexOf('if [[ "$MODE" == rollback ]]; then'));
    assert.ok(releaseBoundary, 'expected release-mode boundary');
    const separator = releaseBoundary.indexOf('\n  else\n');
    assert.ok(separator > 0, 'expected deploy/rollback branch separator');
    const rollbackPath = releaseBoundary.slice(0, separator);
    const targetPath = releaseBoundary.slice(separator + '\n  else\n'.length);

    assert.match(rollbackPath, /ACTIVE_COMPOSE_FILE="\$previous_compose"/);
    assert.doesNotMatch(rollbackPath, /ACTIVE_COMPOSE_FILE="\$target_compose"/);
    assert.match(rollbackPath, /build_control_plane_from_commit "\$SHA"/);
    assert.doesNotMatch(rollbackPath, /git checkout[^\n]*"\$SHA"/);
    assert.match(rollbackPath, /ASTRANULL_WORKER_IMAGE_TAG="\$previous"/);
    assert.match(rollbackPath, /persist_control_plane_image_tag "\$SHA"/);

    assert.match(targetPath, /ACTIVE_COMPOSE_FILE="\$target_compose"[\s\S]*validate_compose[\s\S]*docker build[\s\S]*ensure_postgres_ready_for_backup[\s\S]*backup_database[\s\S]*migrate[\s\S]*up -d/m);
    assert.doesNotMatch(targetPath, /ACTIVE_COMPOSE_FILE="\$previous_compose"/);

    const failureRollback = deploy.slice(
      deploy.indexOf('rollback_on_error()'),
      deploy.indexOf('handle_deploy_exit()'),
    );
    assert.match(failureRollback, /if \[\[ "\$MODE" == rollback \]\][\s\S]*rollback_compose=\$previous_compose[\s\S]*rollback_orchestration_tag=\$previous[\s\S]*else[\s\S]*rollback_compose=\$target_compose[\s\S]*rollback_orchestration_tag=\$SHA/m);
    assert.match(failureRollback, /ASTRANULL_CONTROL_PLANE_IMAGE_TAG="\$previous_control_plane_tag"/);
    assert.match(failureRollback, /verify_control_plane_image_tag "\$previous_control_plane_tag" "\$previous_control_plane_image_id"/);
    assert.match(failureRollback, /verify_workers_image_tag "\$rollback_orchestration_tag"/);
    assert.match(deploy, /prepare_previous_control_plane_image[\s\S]*docker image tag "\$actual_image_id" "\$ref"/m);
    assert.match(deploy, /cleanup_compose_snapshots/);
    assert.match(deploy, /CONTROL_PLANE_IMAGE_TAG_FILE="\$DEPLOY_STATE_DIR\/control-plane-image-tag"/);
  });

  it('creates encrypted backups and health-checks API, edge, workers, and rollback', () => {
    assert.match(deploy, /pg_dump[\s\S]*--format=custom/m);
    assert.match(deploy, /scripts\/postgres-backup\.mjs --input/);
    assert.match(deploy, /\.dump\.enc/);
    assert.match(deploy, /tail -n \+11/);
    assert.match(deploy, /https:\/\/astranull\.site\/health/);
    assert.match(deploy, /probe-worker password-recovery-worker test-policy-runner/);
    assert.match(deploy, /check_control_plane/);
    assert.match(deploy, /postgres-restore-drill\.mjs[\s\S]*--validate-only/m);
    assert.match(deploy, /ASTRANULL_WORKER_IMAGE_TAG="\$previous"/);
    assert.match(deploy, /--rollback/);
    assert.match(deploy, /database was not downgraded/);
    const runbook = read('ops/aws/README.md');
    assert.match(runbook, /backup-dump[\s\S]*?ASTRANULL_BACKUP_DATABASE_URL[\s\S]*?postgres-backup\.mjs --input/m);
    assert.match(runbook, /--database-host postgres --database-port 5432 --database-name astranull/);
    assert.match(runbook, /Until `deploy\.sh` uses this handoff, hosted promotion remains blocked/);
  });

  it('separates owner migrations, backup reads, encryption, and enforced runtime roles', () => {
    const migration = compose.split('  migrate:')[1].split('\n  backup-dump:')[0];
    const dump = compose.split('  backup-dump:')[1].split('\n  backup:')[0];
    const encryption = compose.split('  backup:')[1].split('\n  control-plane:')[0];
    const control = compose.split('  control-plane:')[1].split('\n  probe-worker:')[0];
    const recovery = compose.split('  password-recovery-worker:')[1].split('\n  test-policy-runner:')[0];
    const scheduler = compose.split('  test-policy-runner:')[1].split('\n  caddy:')[0];
    assert.match(migration, /profiles: \["ops"\]/);
    assert.match(migration, /postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
    assert.match(migration, /ASTRANULL_DATABASE_BACKUP_PASSWORD: \$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.match(migration, /migrate-postgres\.mjs && node scripts\/postgres-grant-app-role\.mjs/);
    assert.match(deploy, /--profile ops run --rm --no-deps migrate/);

    assert.match(dump, /postgresql:\/\/astranull_backup:\$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.doesNotMatch(dump, /POSTGRES_PASSWORD|DATABASE_APP_PASSWORD|BACKUP_ENCRYPTION_KEY|SECRET_ENCRYPTION_KEY/);
    assert.match(encryption, /ASTRANULL_BACKUP_ENCRYPTION_KEY/);
    assert.doesNotMatch(encryption, /DATABASE_URL|BACKUP_DATABASE_URL|DATABASE_APP_PASSWORD|DATABASE_BACKUP_PASSWORD|POSTGRES_PASSWORD|SECRET_ENCRYPTION_KEY/);

    for (const runtime of [control, recovery, scheduler]) {
      assert.match(runtime, /postgresql:\/\/astranull_app:/);
      assert.match(runtime, /ASTRANULL_ENFORCE_DATABASE_ROLE: "1"/);
      assert.doesNotMatch(runtime, /postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
      assert.doesNotMatch(runtime, /astranull_backup|ASTRANULL_DATABASE_BACKUP_PASSWORD/);
    }
    assert.match(control, /command: \["node", "src\/index\.mjs"\]/);
    assert.doesNotMatch(control, /env_file:/);
    assert.doesNotMatch(control, /POSTGRES_PASSWORD|BACKUP_ENCRYPTION_KEY|SMTP_PASSWORD/);
    assert.doesNotMatch(compose, /ASTRANULL_DATABASE_(?:APP|BACKUP)_PASSWORD:-|ASTRANULL_BACKUP_ENCRYPTION_KEY:-/);
    assert.match(deploy, /validate-aws-compose-secrets\.mjs/);
  });

  it('keeps worker secrets scoped and exposes failure-visible health', () => {
    const probe = compose.split('  probe-worker:')[1].split('\n  password-recovery-worker:')[0];
    const recovery = compose.split('  password-recovery-worker:')[1].split('\n  test-policy-runner:')[0];
    const scheduler = compose.split('  test-policy-runner:')[1].split('\n  caddy:')[0];
    for (const worker of [probe, recovery, scheduler]) {
      assert.doesNotMatch(worker, /env_file:/);
      assert.match(worker, /healthcheck:/);
    }
    assert.match(probe, /command: \["node", "workers\/probe-worker\.mjs"\]/);
    assert.match(probe, /ASTRANULL_API_URL: http:\/\/control-plane:8080/);
    assert.doesNotMatch(probe, /DATABASE_URL|OIDC|SMTP|SECRET_ENCRYPTION/);
    assert.doesNotMatch(recovery, /OIDC|PROBE_WORKER_SECRET/);
    assert.doesNotMatch(scheduler, /OIDC|SMTP|SECRET_ENCRYPTION/);
    assert.match(scheduler, /test-policy-runner\.heartbeat/);
    assert.match(scheduler, /worker-heartbeat-health\.mjs/);
    const intervalAssignment = scheduler.indexOf('interval=$${ASTRANULL_TEST_POLICY_INTERVAL_SECONDS:-30}');
    const intervalGuard = scheduler.indexOf("*[!0-9]*");
    const loop = scheduler.indexOf('while true');
    const sleep = scheduler.indexOf('sleep "$$interval"');
    assert.ok(intervalAssignment >= 0 && intervalGuard > intervalAssignment && loop > intervalGuard && sleep > loop);
    assert.match(scheduler, /"\$\$interval" -lt 5[\s\S]*?"\$\$interval" -gt 3600/);
    assert.doesNotMatch(scheduler, /sleep \$\$\{ASTRANULL_TEST_POLICY_INTERVAL_SECONDS/);
    assert.match(probe, /worker-heartbeat-health\.mjs/);
    assert.match(recovery, /worker-heartbeat-health\.mjs/);
    assert.match(compose, /postgres:16-alpine@sha256:[0-9a-f]{64}/);
    assert.match(compose, /caddy:2\.8-alpine@sha256:[0-9a-f]{64}/);
  });

  it('restores a verified archive into a clean replacement database and fails closed', () => {
    const restore = read('scripts/postgres-restore-drill.mjs');
    const runbook = read('ops/aws/README.md');
    const restoreScript = read('ops/aws/restore.sh');
    assert.match(restore, /--extract requires --yes/);
    assert.match(restore, /createWriteStream\(extractedTo, \{ flags: 'wx', mode: 0o600 \}\)/);
    assert.doesNotMatch(restore, /readFileSync/);
    assert.match(runbook, /ops\/aws\/restore\.sh --yes/);
    assert.match(restoreScript, /flock -n 9/);
    assert.match(restoreScript, /git status --porcelain --untracked-files=all/);
    assert.match(restoreScript, /trap cleanup EXIT/);
    assert.match(restoreScript, /trap 'exit 130' HUP INT TERM/);
    assert.match(restoreScript, /control_plane_tag=\$\(read_control_plane_image_tag\)/);
    assert.match(restoreScript, /ASTRANULL_CONTROL_PLANE_IMAGE_TAG="\$control_plane_tag"/);
    assert.match(restoreScript, /ASTRANULL_WORKER_IMAGE_TAG="\$orchestration_tag"/);
    assert.match(restoreScript, /verify_running_control_plane_state[\s\S]*stop caddy/m);
    assert.match(restoreScript, /verify_restored_image_identity/);
    assert.match(restoreScript, /restore: ok[^"]*control_plane=astranull-control-plane:\$control_plane_tag@\$control_plane_image_id[^"]*orchestration_workers=\$orchestration_tag/);
    assert.match(restoreScript, /psql -U astranull -d postgres -v ON_ERROR_STOP=1/);
    assert.match(restoreScript, /pg_terminate_backend/);
    assert.match(restoreScript, /DROP DATABASE IF EXISTS astranull WITH \(FORCE\)/);
    assert.match(restoreScript, /CREATE DATABASE astranull WITH OWNER astranull TEMPLATE template0/);
    assert.match(restoreScript, /pg_restore[\s\S]*--single-transaction --exit-on-error --no-owner --no-acl/m);
    assert.doesNotMatch(restoreScript, /pg_restore -U[^\n]*(?:\\\n[^\n]*){0,3}--clean/m);
    assert.doesNotMatch(restoreScript, /docker cp/);
    assert.match(restoreScript, /rm -f -- "\$plain_host"/);
    const cleanupPath = restoreScript.slice(
      restoreScript.indexOf('cleanup()'),
      restoreScript.indexOf('trap cleanup EXIT'),
    );
    assert.match(cleanupPath, /if \(\( ! succeeded \)\); then[\s\S]*compose_timeout 120 stop caddy probe-worker password-recovery-worker test-policy-runner control-plane/m);
    assert.match(cleanupPath, /runtime services remain stopped for operator investigation/);

    const stop = restoreScript.indexOf('stop caddy');
    const verify = restoreScript.indexOf('postgres-restore-drill.mjs');
    const drop = restoreScript.indexOf('DROP DATABASE IF EXISTS');
    const restoreArchive = restoreScript.indexOf('pg_restore -U astranull');
    const migrate = restoreScript.indexOf('--profile ops run --rm --no-deps migrate');
    const activate = restoreScript.indexOf('up -d --remove-orphans');
    assert.ok(stop < verify && verify < drop && drop < restoreArchive && restoreArchive < migrate && migrate < activate);
  });

  it('rejects five-way credential reuse and service-boundary leaks', () => {
    const owner = 'a'.repeat(64);
    const app = 'b'.repeat(64);
    const backupDb = 'c'.repeat(64);
    const backupEncryption = 'd'.repeat(64);
    const envelopeEncryption = 'e'.repeat(64);
    const model = {
      services: {
        postgres: { environment: { POSTGRES_PASSWORD: owner } },
        migrate: { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
          ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
          ASTRANULL_DATABASE_APP_PASSWORD: app,
          ASTRANULL_DATABASE_BACKUP_PASSWORD: backupDb,
        } },
        'backup-dump': { environment: {
          ASTRANULL_BACKUP_DATABASE_URL: `postgresql://astranull_backup:${backupDb}@postgres/astranull`,
        } },
        backup: { environment: {
          NODE_ENV: 'production',
          ASTRANULL_BACKUP_ENCRYPTION_KEY: backupEncryption,
        } },
        'control-plane': { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull_app:${app}@postgres/astranull`,
          ASTRANULL_SECRET_ENCRYPTION_KEY: envelopeEncryption,
        } },
        'probe-worker': { environment: {} },
        'password-recovery-worker': { environment: {
          ASTRANULL_SECRET_ENCRYPTION_KEY: envelopeEncryption,
        } },
        'test-policy-runner': { environment: {} },
      },
    };
    assert.equal(validateAwsComposeSecretModel(model), true);

    model.services.postgres.environment.POSTGRES_PASSWORD = 'f'.repeat(64);
    assert.throws(() => validateAwsComposeSecretModel(model), /owner passwords must match/);
    model.services.postgres.environment.POSTGRES_PASSWORD = owner;

    model.services.migrate.environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = app;
    model.services['backup-dump'].environment.ASTRANULL_BACKUP_DATABASE_URL = `postgresql://astranull_backup:${app}@postgres/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(model), /must all be distinct/);
    model.services.migrate.environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = backupDb;
    model.services['backup-dump'].environment.ASTRANULL_BACKUP_DATABASE_URL = `postgresql://astranull_backup:${backupDb}@postgres/astranull`;

    model.services.backup.environment.ASTRANULL_DATABASE_URL = `postgresql://astranull_backup:${backupDb}@postgres/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(model), /must not receive a database/);
    delete model.services.backup.environment.ASTRANULL_DATABASE_URL;

    model.services['control-plane'].environment.ASTRANULL_BACKUP_DATABASE_URL = `postgresql://astranull_backup:${backupDb}@postgres/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(model), /operator-only credential/);
    delete model.services['control-plane'].environment.ASTRANULL_BACKUP_DATABASE_URL;

    model.services['backup-dump'].environment.ASTRANULL_BACKUP_ENCRYPTION_KEY = backupEncryption;
    assert.throws(() => validateAwsComposeSecretModel(model), /may receive only its backup database URL/);
  });

  it('makes deploy artifact parsing a prerequisite of CI success', () => {
    assert.match(ci, /bash -n ops\/aws\/deploy\.sh/);
    assert.match(ci, /bash -n ops\/aws\/restore\.sh/);
    assert.match(ci, /validate-aws-compose-secrets\.mjs/);
    assert.match(ci, /docker compose[\s\S]*config --no-interpolate --no-path-resolution/m);
    assert.match(ci, /docker build -f ops\/aws\/Dockerfile -t astranull-ci-check/);
  });
});
