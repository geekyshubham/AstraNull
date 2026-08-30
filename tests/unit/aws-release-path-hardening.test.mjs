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

  it('makes docker compose up image-only so it cannot build from the AWS worktree', () => {
    const servicesStart = compose.indexOf('services:\n') + 'services:\n'.length;
    const servicesEnd = compose.indexOf('\nvolumes:', servicesStart);
    const servicesSource = compose.slice(servicesStart, servicesEnd);
    const declarations = [...servicesSource.matchAll(/^  ([a-z0-9-]+):\n/gm)];

    assert.ok(servicesStart >= 'services:\n'.length, 'expected a services block');
    assert.ok(servicesEnd > servicesStart, 'expected the services block to end before volumes');
    assert.ok(declarations.length > 0, 'expected at least one AWS Compose service');
    assert.doesNotMatch(compose, /^\s+(?:build|context|dockerfile):/m);

    for (const [index, declaration] of declarations.entries()) {
      const next = declarations[index + 1];
      const block = servicesSource.slice(declaration.index, next?.index ?? servicesSource.length);
      assert.match(block, /^    image:\s+\S+/m, `${declaration[1]} must use a prebuilt image`);
    }

    const helper = deploy.match(/^build_control_plane_from_commit\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(helper, /git archive "\$commit"/);
    assert.match(helper, /docker build -f ops\/aws\/Dockerfile/);
    assert.match(helper, /-t "astranull-control-plane:\$commit" -/);
    assert.equal((deploy.match(/\bdocker build\b/g) ?? []).length, 1);
  });

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
    assert.match(deploy, /compose_timeout 90 --profile ops run --rm --no-deps backup-role-bootstrap/);
    assert.match(deploy, /compose_timeout 180 --profile ops run --rm --no-deps[\s\S]*backup-dump[\s\S]*pg_dump/m);
    const backupFunction = deploy.slice(deploy.indexOf('backup_database()'), deploy.indexOf('rollback_on_error()'));
    assert.doesNotMatch(backupFunction, /postgres_cid=|docker cp/);
    assert.doesNotMatch(deploy, /\$\(compose ps -q/);
    assert.match(deploy, /compose_timeout 180[\s\S]*postgres-backup\.mjs/m);
    assert.match(deploy, /timeout -k 30 480 docker build/);
    assert.match(deploy, /git archive "\$commit" \\[\s\S]*docker build -f ops\/aws\/Dockerfile[\s\S]*-t "astranull-control-plane:\$commit" -/m);
    assert.match(deploy, /--wait --wait-timeout 240/);
  });

  it('runs release JSON parsing only in an isolated immutable control-plane image', () => {
    const restore = read('ops/aws/restore.sh');
    const logicalCommands = (source) => source.replace(/\\\n\s*/g, ' ');
    const hostNodeCommand = /(?:^|[|;&]\s*)(?:(?:exec\s+)|(?:timeout(?:\s+-k\s+\S+)?\s+\S+\s+))?node\b/m;

    for (const [name, source] of [['deploy', deploy], ['restore', restore]]) {
      const runner = source.match(/^run_control_plane_node\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const validator = source.match(/^validate_compose\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      assert.match(runner, /\[\[ "\$image_id" =~ \^sha256:\[0-9a-f\]\{64\}\$ \]\]/, `${name} must require an immutable image ID`);
      assert.match(runner, /docker run --network none --read-only --user 10001:10001 --rm -i \\/);
      assert.match(runner, /"\$image_id" node "\$@"/);
      assert.doesNotMatch(runner, /--env(?:-file)?|--mount|(?:^|\s)-v(?:\s|$)/m);
      assert.match(validator, /config --format json \\[\s\S]*\| run_control_plane_node "\$image_id" scripts\/validate-aws-compose-secrets\.mjs/m);
      assert.doesNotMatch(validator, /mktemp|tee|--env(?:-file)?|--mount|(?:^|\s)-v(?:\s|$)/m);
      assert.doesNotMatch(logicalCommands(source), hostNodeCommand, `${name} must not execute host-side node`);
      assert.doesNotMatch(source, /\$\(\s*node\b/, `${name} must not execute host-side node in command substitution`);
    }

    const volumeParser = deploy.match(/^postgres_volume_name\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(volumeParser, /config --format json \\[\s\S]*\| run_control_plane_node "\$image_id" -e/m);
    assert.doesNotMatch(volumeParser, /mktemp|tee|--env(?:-file)?|--mount|(?:^|\s)-v(?:\s|$)/m);
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
    assert.match(rollbackPath, /validator_image_id=\$\(image_id_for_ref "astranull-control-plane:\$previous"\)[\s\S]*validate_compose "\$validator_image_id"[\s\S]*backup_database[\s\S]*build_control_plane_from_commit "\$SHA"/m);
    assert.match(rollbackPath, /build_control_plane_from_commit "\$SHA"/);
    assert.doesNotMatch(rollbackPath, /git checkout[^\n]*"\$SHA"/);
    assert.match(rollbackPath, /ASTRANULL_WORKER_IMAGE_TAG="\$previous"/);
    assert.match(rollbackPath, /persist_control_plane_image_state "\$SHA" "\$active_control_plane_image_id"/);

    assert.match(targetPath, /ACTIVE_COMPOSE_FILE="\$target_compose"[\s\S]*build_control_plane_from_commit "\$SHA"[\s\S]*validator_image_id=\$\(image_id_for_ref "astranull-control-plane:\$SHA"\)[\s\S]*validate_compose "\$validator_image_id"[\s\S]*ensure_postgres_ready_for_backup "\$validator_image_id"[\s\S]*backup_database[\s\S]*migrate[\s\S]*up -d/m);
    assert.doesNotMatch(targetPath, /docker build[^\n]*\s\.(?:\s|$)/m);
    assert.doesNotMatch(targetPath, /ACTIVE_COMPOSE_FILE="\$previous_compose"/);

    const failureRollback = deploy.slice(
      deploy.indexOf('rollback_on_error()'),
      deploy.indexOf('handle_deploy_exit()'),
    );
    assert.match(failureRollback, /if \[\[ "\$MODE" == rollback \]\][\s\S]*rollback_compose=\$previous_compose[\s\S]*rollback_orchestration_tag=\$previous[\s\S]*else[\s\S]*rollback_compose=\$target_compose[\s\S]*rollback_orchestration_tag=\$SHA/m);
    assert.match(failureRollback, /ASTRANULL_CONTROL_PLANE_IMAGE_TAG="\$previous_control_plane_tag"/);
    assert.match(failureRollback, /rebind_control_plane_image_tag "\$previous_control_plane_tag" "\$previous_control_plane_image_id"/);
    assert.match(failureRollback, /verify_control_plane_image_tag "\$previous_control_plane_tag" "\$previous_control_plane_image_id"/);
    assert.match(failureRollback, /verify_workers_image_tag "\$rollback_orchestration_tag"/);
    assert.match(failureRollback, /persist_control_plane_image_state "\$previous_control_plane_tag" "\$previous_control_plane_image_id"/);
    assert.ok(
      failureRollback.indexOf('rebind_control_plane_image_tag') < failureRollback.indexOf('compose_timeout 300 up'),
      'automatic rollback must rebind the preserved ID before activation',
    );
    assert.match(deploy, /prepare_previous_control_plane_image[\s\S]*docker image tag "\$actual_image_id" "\$ref"/m);
    assert.match(deploy, /cleanup_compose_snapshots/);
    assert.match(deploy, /CONTROL_PLANE_IMAGE_TAG_FILE="\$DEPLOY_STATE_DIR\/control-plane-image-tag"/);
    assert.match(deploy, /printf '%s\\n%s\\n' "\$tag" "\$image_id"/);
    assert.match(deploy, /read_control_plane_image_id/);
  });

  it('creates encrypted backups and health-checks API, edge, workers, and rollback', () => {
    assert.match(deploy, /--profile ops run --rm --no-deps[\s\\]*[\s\S]*backup-dump[\s\S]*pg_dump[\s\S]*ASTRANULL_BACKUP_DATABASE_URL/m);
    assert.doesNotMatch(deploy, /exec -T postgres pg_dump|pg_dump -U astranull/);
    assert.match(deploy, /scripts\/postgres-backup\.mjs[\s\S]*--input[\s\S]*--database-host postgres --database-port 5432 --database-name astranull/m);
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
    assert.match(runbook, /`deploy\.sh` implements this exact handoff/);
  });

  it('separates owner migrations, backup reads, encryption, and enforced runtime roles', () => {
    const migration = compose.split('  migrate:')[1].split('\n  backup-role-bootstrap:')[0];
    const bootstrap = compose.split('  backup-role-bootstrap:')[1].split('\n  backup-dump:')[0];
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

    assert.match(bootstrap, /ASTRANULL_ADMIN_DATABASE_URL: postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
    assert.match(bootstrap, /ASTRANULL_DATABASE_BACKUP_PASSWORD: \$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.match(bootstrap, /postgres-grant-app-role\.mjs", "--backup-only"/);
    assert.doesNotMatch(bootstrap, /DATABASE_APP_PASSWORD|BACKUP_ENCRYPTION_KEY|SECRET_ENCRYPTION_KEY/);
    assert.match(deploy, /--profile ops run --rm --no-deps backup-role-bootstrap/);

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
    const runner = read('scripts/test-policy-runner.mjs');
    const envExample = read('ops/aws/env.example');
    assert.match(scheduler, /test-policy-runner\.heartbeat/);
    assert.match(scheduler, /worker-heartbeat-health\.mjs/);
    assert.match(scheduler, /restart: unless-stopped/);
    const intervalAssignment = scheduler.indexOf('interval=$${ASTRANULL_TEST_POLICY_INTERVAL_SECONDS:-30}');
    const intervalGuard = scheduler.indexOf("*[!0-9]*");
    const loop = scheduler.indexOf('while true');
    const sleep = scheduler.indexOf('sleep "$$interval"');
    assert.ok(intervalAssignment >= 0 && intervalGuard > intervalAssignment && loop > intervalGuard && sleep > loop);
    assert.match(scheduler, /"\$\$interval" -lt 5[\s\S]*?"\$\$interval" -gt 30/);
    assert.doesNotMatch(scheduler, /sleep \$\$\{ASTRANULL_TEST_POLICY_INTERVAL_SECONDS/);

    const boundedTick = scheduler.match(
      /if timeout -k 10 (\d+) node scripts\/test-policy-runner\.mjs; then([\s\S]*?)else([\s\S]*?)fi;/,
    );
    assert.ok(boundedTick, 'expected a bounded policy tick with explicit success and failure branches');
    const tickLimitSeconds = Number(boundedTick[1]);
    const maxSleepSeconds = Number(scheduler.match(/"\$\$interval" -gt (\d+)/)?.[1]);
    const freshnessSeconds = Number(scheduler.match(
      /worker-heartbeat-health\.mjs", "\/tmp\/test-policy-runner\.heartbeat", "(\d+)"/,
    )?.[1]);
    assert.equal(tickLimitSeconds, 120);
    assert.equal(maxSleepSeconds, 30);
    assert.equal(freshnessSeconds, 180);
    assert.ok(
      freshnessSeconds - tickLimitSeconds - maxSleepSeconds >= 30,
      'successful max-duration tick plus max sleep must retain at least 30s freshness margin',
    );
    assert.match(boundedTick[2], /date -u \+%FT%TZ > \/tmp\/test-policy-runner\.heartbeat/);
    assert.doesNotMatch(boundedTick[3], /heartbeat|date -u/);
    assert.match(boundedTick[3], /bounded invocation failed/);

    assert.match(runner, /TEST_POLICY_SCHEDULER_MAX_INTERVAL_SECONDS = 30/);
    assert.match(runner, /ASTRANULL_TEST_POLICY_INTERVAL_SECONDS \(optional; 5-30, default 30\)/);
    assert.match(envExample, /valid range 5-30[\s\S]*ASTRANULL_TEST_POLICY_INTERVAL_SECONDS=30/);
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
    assert.match(restoreScript, /control_plane_image_id=\$\(read_control_plane_image_id\)/);
    assert.match(restoreScript, /rebind_control_plane_image_tag/);
    assert.match(restoreScript, /ASTRANULL_CONTROL_PLANE_IMAGE_TAG="\$control_plane_tag"/);
    assert.match(restoreScript, /ASTRANULL_WORKER_IMAGE_TAG="\$orchestration_tag"/);
    assert.match(restoreScript, /verify_running_control_plane_state[\s\S]*stop caddy/m);
    assert.match(restoreScript, /verify_restored_image_identity/);
    assert.match(restoreScript, /load_restore_image_identity[\s\S]*validate_compose "\$control_plane_image_id"[\s\S]*verify_running_control_plane_state/m);
    const loadIdentity = restoreScript.slice(
      restoreScript.indexOf('load_restore_image_identity()'),
      restoreScript.indexOf('verify_service_image_tag()'),
    );
    assert.ok(
      loadIdentity.indexOf('rebind_control_plane_image_tag') < loadIdentity.indexOf('worker_image_id=$(image_id_for_ref'),
      'restore must rebind persisted control-plane identity before same-tag worker resolution',
    );
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

    const restoreMain = restoreScript.slice(restoreScript.indexOf('main()'));
    const loadIdentityIndex = restoreMain.indexOf('load_restore_image_identity');
    const validate = restoreMain.indexOf('validate_compose "$control_plane_image_id"');
    const verifyRunning = restoreMain.indexOf('verify_running_control_plane_state');
    const stop = restoreMain.indexOf('stop caddy');
    const verify = restoreMain.indexOf('postgres-restore-drill.mjs');
    const drop = restoreMain.indexOf('DROP DATABASE IF EXISTS');
    const restoreArchive = restoreMain.indexOf('pg_restore -U astranull');
    const migrate = restoreMain.indexOf('--profile ops run --rm --no-deps migrate');
    const activate = restoreMain.indexOf('up -d --remove-orphans');
    assert.ok(loadIdentityIndex < validate && validate < verifyRunning && verifyRunning < stop);
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
        'backup-role-bootstrap': { environment: {
          NODE_ENV: 'production',
          ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
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
    model.services['backup-role-bootstrap'].environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = app;
    model.services['backup-dump'].environment.ASTRANULL_BACKUP_DATABASE_URL = `postgresql://astranull_backup:${app}@postgres/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(model), /must all be distinct/);
    model.services.migrate.environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = backupDb;
    model.services['backup-role-bootstrap'].environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = backupDb;
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
