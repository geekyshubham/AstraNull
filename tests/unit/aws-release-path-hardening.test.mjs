import { generateKeyPairSync } from 'node:crypto';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  connectorWorkloadsEnabled,
  validateAwsComposeSecretModel,
  validatedAwsComposeConnectorMode,
  wafPostureEnabled,
} from '../../scripts/validate-aws-compose-secrets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relative) => readFileSync(path.join(ROOT, relative), 'utf8');

describe('AWS release path hardening', () => {
  const workflow = read('.github/workflows/deploy-aws.yml');
  const ci = read('.github/workflows/ci.yml');
  const deploy = read('ops/aws/deploy.sh');
  const releaseState = read('ops/aws/release-state.sh');
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

    const appImageVariables = {
      migrate: 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      'backup-role-bootstrap': 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      backup: 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      'control-plane': 'ASTRANULL_CONTROL_PLANE_IMAGE_ID',
      'probe-worker': 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      'password-recovery-worker': 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      'test-policy-runner': 'ASTRANULL_CORE_WORKER_IMAGE_ID',
      'connector-poll-scheduler': 'ASTRANULL_CONNECTOR_WORKER_IMAGE_ID',
      'connector-poll-runner': 'ASTRANULL_CONNECTOR_WORKER_IMAGE_ID',
    };
    for (const [service, variable] of Object.entries(appImageVariables)) {
      const declaration = declarations.find((entry) => entry[1] === service);
      assert.ok(declaration, `missing ${service}`);
      const declarationIndex = declarations.indexOf(declaration);
      const next = declarations[declarationIndex + 1];
      const block = servicesSource.slice(declaration.index, next?.index ?? servicesSource.length);
      assert.match(
        block,
        new RegExp(`^    image: "\\$\\{${variable}:\\?${variable} is required\\}"$`, 'm'),
        `${service} must bind directly to ${variable}`,
      );
    }
    assert.doesNotMatch(
      compose,
      /ASTRANULL_(?:IMAGE|CONTROL_PLANE_IMAGE|WORKER_IMAGE|CONNECTOR_WORKER_IMAGE)_TAG/,
    );

    const helper = deploy.match(/^build_control_plane_from_commit\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(helper, /git archive "\$commit"/);
    assert.match(helper, /docker build --iidfile "\$iid_file"/);
    assert.match(helper, /-f ops\/aws\/Dockerfile -t "astranull-control-plane:\$commit" -/);
    assert.match(helper, /built_control_plane_image_id=\$image_id/);
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
    assert.match(workflow, /state_lib_sha256=\$\(sha256sum ops\/aws\/release-state\.sh/);
    assert.match(workflow, /scp[\s\S]*ops\/aws\/release-state\.sh[\s\S]*remote_state_lib/m);
    assert.match(workflow, /state_lib_sha256[\s\S]*sha256sum -c -[\s\S]*ASTRANULL_RELEASE_STATE_LIB='\$remote_state_lib'/m);
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
    assert.match(deploy, /compose_ops_run 90 backup-role-bootstrap backup-role-bootstrap/);
    assert.match(deploy, /compose_ops_run 180 pg-dump[\s\S]*backup-dump[\s\S]*pg_dump/m);
    const backupFunction = deploy.slice(deploy.indexOf('backup_database()'), deploy.indexOf('rollback_on_error()'));
    assert.doesNotMatch(backupFunction, /postgres_cid=|docker cp/);
    assert.doesNotMatch(deploy, /\$\(compose ps -q/);
    assert.match(deploy, /compose_ops_run 180 backup-encrypt[\s\S]*postgres-backup\.mjs/m);
    assert.match(deploy, /timeout -k 30 480 docker build/);
    assert.match(deploy, /git archive "\$commit" \\[\s\S]*docker build --iidfile "\$iid_file"[\s\S]*-f ops\/aws\/Dockerfile -t "astranull-control-plane:\$commit" -/m);
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
      assert.match(runner, /docker run --name "\$name" --network none --read-only/);
      assert.match(runner, /--user 10001:10001 -i "\$image_id" node "\$@"/);
      assert.match(runner, /remove_named_container_checked "\$name"/);
      assert.doesNotMatch(runner, /--rm/);
      assert.doesNotMatch(runner, /--env(?:-file)?|--mount|(?:^|\s)-v(?:\s|$)/m);
      assert.match(validator, /config --format json > "\$COMPOSE_RENDER_FILE"/);
      assert.match(validator, /validator_output=\$\(run_control_plane_node "\$image_id" scripts\/validate-aws-compose-secrets\.mjs --print-connector-mode < "\$COMPOSE_RENDER_FILE"\)/);
      assert.match(validator, /enabled\|disabled\) resolved_mode=\$validator_output/);
      assert.match(validator, /current release-image Compose validator returned an unexpected result/);
      assert.doesNotMatch(validator, /aws-compose-secrets: ok|compatibility_output|aws-compose-compat|--input-type=module/);
      assert.match(validator, /cleanup_compose_render_checked/);
      assert.equal((validator.match(/config --format json/g) ?? []).length, 1, `${name} must render once per mode decision`);
      assert.doesNotMatch(source, /connector_release_mode/);
      assert.doesNotMatch(validator, /mktemp|tee|--env(?:-file)?|--mount/m);
      assert.doesNotMatch(logicalCommands(source), hostNodeCommand, `${name} must not execute host-side node`);
      assert.doesNotMatch(source, /\$\(\s*node\b/, `${name} must not execute host-side node in command substitution`);
    }

    const volumeParser = deploy.match(/^postgres_volume_name\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(volumeParser, /config --format json \\[\s\S]*\| run_control_plane_node "\$image_id" -e/m);
    assert.doesNotMatch(volumeParser, /mktemp|tee|--env(?:-file)?|--mount|(?:^|\s)-v(?:\s|$)/m);
  });

  it('uses one private env snapshot and deterministic checked cleanup for every one-shot', () => {
    const restore = read('ops/aws/restore.sh');
    for (const [name, source] of [['deploy', deploy], ['restore', restore]]) {
      const sourceValidator = source.match(/^validate_env_source\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const snapshot = source.match(/^snapshot_env_file\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const composeHelper = source.match(/^compose_timeout\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const opsHelper = source.match(/^compose_ops_run\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const removeHelper = source.match(/^remove_named_container_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const operationCleanup = source.match(/^cleanup_active_operation_containers_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const operationNames = source.match(/^operation_container_names\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const renderCreator = source.match(/^create_compose_render_file\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const renderCleanup = source.match(/^cleanup_compose_render_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const identityVerifier = source.match(/^verify_service_image_tag\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const plaintextHelper = source.match(/^delete_plaintext_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const main = source.slice(source.indexOf('main()'));

      assert.match(sourceValidator, /-f "\$ENV_FILE" && ! -L "\$ENV_FILE"/);
      assert.match(sourceValidator, /env_mode[\s\S]*(?:400|600)[\s\S]*(?:400|600)/);
      assert.match(sourceValidator, /env_owner[\s\S]*env_links/);
      assert.match(snapshot, /refusing to replace an existing environment snapshot/);
      assert.match(snapshot, new RegExp(`mktemp "\\$BACKUP_DIR/\\.astranull-env\\.${name}\\.XXXXXX"`));
      assert.match(snapshot, /chmod 600 "\$ENV_SNAPSHOT"/);
      assert.match(snapshot, /cat -- "\$ENV_FILE" > "\$ENV_SNAPSHOT"/);
      assert.match(snapshot, /changed while it was being snapshotted or the snapshot is unsafe/);
      assert.equal((source.match(/^  snapshot_env_file$/gm) ?? []).length, 1, `${name} must snapshot once`);
      assert.ok(main.indexOf('snapshot_env_file') < main.indexOf('validate_compose'), `${name} must snapshot before model validation`);
      assert.match(composeHelper, /mode-0600 environment snapshot/);
      assert.match(composeHelper, /--env-file "\$ENV_SNAPSHOT"/);
      assert.doesNotMatch(composeHelper, /--env-file "\$ENV_FILE"/);

      assert.match(opsHelper, new RegExp(`name="astranull-${name}-\\$\\{purpose\\}-\\$\\$"`));
      assert.match(opsHelper, /compose_timeout "\$duration" --profile ops run --name "\$name" --no-deps/);
      assert.match(opsHelper, /remove_named_container_checked "\$name"/);
      assert.match(opsHelper, /return 125/);
      assert.doesNotMatch(opsHelper, /--rm/);
      assert.equal((source.match(/--profile ops run/g) ?? []).length, 1, `${name} ops runs must use the helper`);
      assert.match(removeHelper, /timeout -k 5 30 docker rm -f -- "\$name"/);
      assert.match(removeHelper, /verify_named_container_absent "\$name"/);
      assert.ok(operationNames.includes(`name=^astranull-${name}-[a-z0-9-]+-$$\\$`));
      assert.match(operationCleanup, /operation_container_names[\s\S]*remove_named_container_checked[\s\S]*operation_container_names/m);
      assert.match(operationCleanup, /operation container still exists after parent cleanup/);
      assert.ok(source.includes(`$BACKUP_DIR/.astranull-compose-render.${name}.$$`));
      assert.match(renderCreator, /set -o noclobber/);
      assert.match(renderCreator, /chmod 600 "\$COMPOSE_RENDER_FILE"/);
      assert.match(renderCleanup, /if ! rm -f -- "\$COMPOSE_RENDER_FILE"/);
      assert.match(renderCleanup, /private Compose render still exists/);

      assert.match(identityVerifier, /Config\.Image/);
      assert.match(identityVerifier, /"\$image_ref" == "\$expected_image_id"/);
      assert.match(identityVerifier, /"\$container_image_id" == "\$expected_image_id"/);
      assert.match(plaintextHelper, /if ! rm -f -- "\$candidate"/);
      assert.match(plaintextHelper, /\[\[ -e "\$candidate" \|\| -L "\$candidate" \]\]/);
      assert.match(plaintextHelper, /CRITICAL: plaintext backup still exists/);
      assert.ok((source.match(/delete_plaintext_checked "\$plain_host"/g) ?? []).length >= 2);
    }

    const restoreAllocator = restore.match(/^allocate_restore_plaintext_path\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    const restoreStaleCleanup = restore.match(/^cleanup_stale_plaintext_archives\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    const deployOrphanCleanup = deploy.match(/^cleanup_backup_orphans\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(restoreAllocator, /mktemp "\$BACKUP_DIR\/\.astranull-plaintext\.restore\.XXXXXX"/);
    assert.match(restoreAllocator, /restore_plaintext_file_security "\$plain_host" allocation/);
    assert.match(restoreAllocator, /\[\[ ! -e "\$plain_host" && ! -L "\$plain_host" \]\]/);
    assert.doesNotMatch(restore, /\.restore-\$\{core_worker_tag\}-\$\$\.dump/);
    assert.ok(restore.indexOf('allocate_restore_plaintext_path', restore.indexOf('main()'))
      < restore.indexOf('compose_ops_run 180 backup-decrypt', restore.indexOf('main()')));
    for (const cleanup of [restoreStaleCleanup, deployOrphanCleanup]) {
      assert.match(cleanup, /\.astranull-plaintext\.deploy\.\*/);
      assert.match(cleanup, /\.astranull-plaintext\.restore\.\*/);
      assert.match(cleanup, /delete_plaintext_checked/);
    }

    const deployCleanup = deploy.match(/^cleanup_compose_snapshots\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    const restoreCleanup = restore.match(/^cleanup_env_snapshot_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    for (const cleanup of [deployCleanup, restoreCleanup]) {
      assert.match(cleanup, /if ! rm -f -- "\$ENV_SNAPSHOT"/);
      assert.match(cleanup, /\[\[ -e "\$ENV_SNAPSHOT" \|\| -L "\$ENV_SNAPSHOT" \]\]/);
      assert.match(cleanup, /CRITICAL: private environment snapshot still exists/);
    }
  });

  it('locks a private inode and sweeps SIGKILL leftovers before release work', () => {
    const restore = read('ops/aws/restore.sh');
    for (const [name, source] of [['deploy', deploy], ['restore', restore]]) {
      const lock = source.match(/^acquire_deploy_lock\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const staleContainers = source.match(/^cleanup_stale_operation_containers_checked\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const staleWorkspace = source.match(/^cleanup_stale_release_workspace\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      const main = source.slice(source.indexOf('main()'));
      assert.match(source, /DEPLOY_LOCK_FILE="\$BACKUP_DIR\/deploy\.lock"/);
      assert.doesNotMatch(source, /exec 9>\/tmp\/astranull-deploy\.lock/);
      assert.match(lock, /st_nlink != 1/);
      assert.match(lock, /path_stat\.st_dev, path_stat\.st_ino/);
      assert.match(lock, /fd_stat\.st_dev, fd_stat\.st_ino/);
      assert.match(staleContainers, /all_release_operation_container_names[\s\S]*remove_named_container_checked/m);
      assert.match(staleWorkspace, /\.astranull-env\.deploy\.\*[\s\S]*\.astranull-env\.restore\.\*/m);
      assert.ok(main.indexOf('cleanup_stale_operation_containers_checked') < main.indexOf('cleanup_stale_release_workspace'));
      assert.ok(main.indexOf('cleanup_stale_release_workspace') < main.indexOf('snapshot_env_file'));
      if (name === 'deploy') {
        assert.ok(main.indexOf('install_failure_traps') < main.indexOf('snapshot_env_file'));
      }
    }
    assert.match(compose, /migrate:[\s\S]*exec timeout -k 10 150[\s\S]*migrate-postgres\.mjs/m);
    const restoreMain = restore.slice(restore.indexOf('main()'));
    const restorePreReconcile = restoreMain.slice(0, restoreMain.indexOf('reconcile_pending_release_bundle'));
    assert.match(restorePreReconcile, /if pending_release_bundle_exists; then[\s\S]*export_compose_image_ids[\s\S]*elif canonical_release_bundle_exists; then[\s\S]*release_bundle_load "\$CURRENT_RELEASE_BUNDLE_FILE"[\s\S]*export_compose_image_ids/m);
    assert.ok(restoreMain.indexOf('load_expected_plaintext_sha256') < restoreMain.indexOf('backup-decrypt'));
    assert.ok((restoreMain.match(/validate_plaintext_archive "\$plain_host"/g) ?? []).length >= 3);
    assert.match(restore, /restore_plaintext_sha256[\s\S]*expected_plaintext_sha256/m);
  });

  it('uses exact three-way identities across target deploy, explicit rollback, and failure rollback', () => {
    assert.match(deploy, /previous_compose=\$\(mktemp/);
    assert.match(deploy, /target_compose=\$\(mktemp/);
    assert.match(deploy, /git show "\$previous:\$COMPOSE_REPO_PATH" > "\$previous_compose"/);
    assert.match(deploy, /git show "\$SHA:\$COMPOSE_REPO_PATH" > "\$target_compose"/);

    const releaseBoundary = deploy.slice(deploy.lastIndexOf('if [[ "$MODE" == rollback ]]; then'));
    const separator = releaseBoundary.indexOf('\n  else\n');
    assert.ok(separator > 0, 'expected deploy/rollback branch separator');
    const rollbackPath = releaseBoundary.slice(0, separator);
    const targetPath = releaseBoundary.slice(separator + '\n  else\n'.length);

    assert.match(rollbackPath, /ACTIVE_COMPOSE_FILE="\$previous_compose"/);
    assert.match(rollbackPath, /ASTRANULL_IMAGE_TAG="\$previous_core_worker_tag"/);
    assert.match(rollbackPath, /ASTRANULL_WORKER_IMAGE_TAG="\$previous_core_worker_tag"/);
    assert.match(rollbackPath, /export_compose_image_ids[\s\S]*validator_image_id=\$release_validator_image_id[\s\S]*validate_compose "\$validator_image_id" validated_connector_mode[\s\S]*assert_target_image_identity_compatible[\s\S]*backup_database/m);
    assert.match(rollbackPath, /assert_target_image_identity_compatible "\$SHA" "\$active_control_plane_image_id"/);
    assert.match(rollbackPath, /connector_image_supports_split_mode "\$active_control_plane_image_id"[\s\S]*lacks split connector mode required by retained Compose[\s\S]*backup_database/m);
    assert.ok(rollbackPath.indexOf('connector_image_supports_split_mode "$active_control_plane_image_id"')
      < rollbackPath.indexOf('backup_database'));
    assert.doesNotMatch(rollbackPath, /git checkout[^\n]*"\$SHA"/);
    assert.ok(
      rollbackPath.indexOf('start_core_stack') < rollbackPath.indexOf('start_connector_workers'),
      'explicit rollback must verify core before compatible connectors',
    );
    assert.match(rollbackPath, /verify_workers_image_tag "\$active_core_worker_tag" "\$active_core_worker_image_id"/);
    assert.match(rollbackPath, /write_pending_release_bundle[\s\S]*"\$active_core_worker_tag" "\$active_core_worker_image_id"/);
    assert.match(rollbackPath, /promote_pending_release_bundle/);
    assert.match(rollbackPath, /verify_services_absent connector-poll-scheduler connector-poll-runner/);

    assert.match(targetPath, /ACTIVE_COMPOSE_FILE="\$target_compose"[\s\S]*validator_image_id=\$requested_image_id[\s\S]*export_compose_image_ids[\s\S]*validate_compose "\$validator_image_id" validated_connector_mode[\s\S]*assert_target_image_identity_compatible[\s\S]*ensure_postgres_ready_for_backup[\s\S]*backup_database[\s\S]*compose_ops_run 180 migrate migrate[\s\S]*start_core_stack/m);
    assert.match(targetPath, /verify_workers_image_tag "\$active_core_worker_tag" "\$active_core_worker_image_id"/);
    assert.match(targetPath, /write_pending_release_bundle[\s\S]*promote_pending_release_bundle/m);
    assert.match(targetPath, /verify_services_absent connector-poll-scheduler connector-poll-runner/);
    assert.match(targetPath, /rebind_release_validator_image_tag "\$release_validator_tag" "\$release_validator_image_id"/);
    assert.doesNotMatch(targetPath, /persist_(?:control_plane|core_worker|connector|release_validator)_image_state/);
    assert.ok(targetPath.indexOf('validate_compose "$validator_image_id"')
      < targetPath.indexOf('write_pending_release_bundle'));
    assert.ok(targetPath.indexOf('write_pending_release_bundle')
      < targetPath.indexOf('ensure_postgres_ready_for_backup'));
    assert.ok(targetPath.indexOf('promote_pending_release_bundle')
      < targetPath.indexOf('git checkout -q --detach "$SHA"'));
    assert.ok(targetPath.indexOf('git checkout -q --detach "$SHA"')
      < targetPath.indexOf('finished=1'));
    assert.ok(targetPath.indexOf('ensure_postgres_ready_for_backup')
      < targetPath.indexOf('compose_ops_run 180 migrate migrate'));
    assert.ok(targetPath.indexOf('compose_ops_run 180 migrate migrate')
      < targetPath.indexOf('start_core_stack'));
    assert.doesNotMatch(rollbackPath, /persist_release_validator_image_state/);
    assert.doesNotMatch(targetPath, /docker build[^\n]*\s\.(?:\s|$)/m);

    const failureRollback = deploy.slice(
      deploy.indexOf('rollback_on_error()'),
      deploy.indexOf('handle_deploy_exit()'),
    );
    assert.match(failureRollback, /rollback_checkout_tag=\$previous[\s\S]*rollback_checkout_tag=\$SHA/m);
    assert.match(failureRollback, /ASTRANULL_IMAGE_TAG="\$previous_core_worker_tag"/);
    assert.match(failureRollback, /ASTRANULL_WORKER_IMAGE_TAG="\$previous_core_worker_tag"/);
    assert.match(failureRollback, /rebind_control_plane_image_tag "\$previous_control_plane_tag" "\$previous_control_plane_image_id"/);
    assert.match(failureRollback, /rebind_core_worker_image_tag "\$previous_core_worker_tag" "\$previous_core_worker_image_id"/);
    assert.match(failureRollback, /verify_workers_image_tag "\$previous_core_worker_tag" "\$previous_core_worker_image_id"/);
    assert.match(failureRollback, /rollback_validator_tag=\$previous_release_validator_tag[\s\S]*rollback_validator_tag=\$release_validator_tag/m);
    assert.match(failureRollback, /write_pending_release_bundle[\s\S]*rollback_validator_tag[\s\S]*promote_pending_release_bundle/m);
    assert.match(failureRollback, /previous_connector_enabled[\s\S]*rebind_connector_image_tag[\s\S]*connector_image_supports_split_mode/m);
    assert.match(failureRollback, /rollback_failed[\s\S]*if fail_closed_runtime; then[\s\S]*shutdown could not be verified/m);
    assert.doesNotMatch(failureRollback, /persist_release_validator_image_state/);
    assert.ok(
      failureRollback.indexOf('rebind_core_worker_image_tag') < failureRollback.indexOf('start_core_stack'),
      'automatic rollback must rebind core ID before activation',
    );

    assert.match(deploy, /CORE_WORKER_IMAGE_STATE_FILE="\$DEPLOY_STATE_DIR\/core-worker-image-state"/);
    assert.match(deploy, /CONNECTOR_IMAGE_STATE_FILE="\$DEPLOY_STATE_DIR\/connector-image-state"/);
    assert.match(deploy, /RELEASE_VALIDATOR_IMAGE_STATE_FILE="\$DEPLOY_STATE_DIR\/release-validator-image-state"/);
    assert.match(deploy, /if \[\[ "\$MODE" == rollback \]\]; then\n\s+load_release_validator_image_identity/);
    assert.match(deploy, /prepare_previous_release_images "\$SHA"/);
    assert.match(deploy, /legacy core workers do not share one exact Config\.Image and immutable image ID/);
    assert.match(deploy, /legacy control\/core release is incomplete; all four services must be running/);
    assert.match(deploy, /assert_genuinely_fresh_host "\$requested_image_id"/);
    assert.match(deploy, /ps --all -q postgres/);
    assert.match(deploy, /docker_volume_exists "\$volume_name"/);
    assert.doesNotMatch(deploy, /read_control_plane_image_tag "\$previous"|image_id_for_ref "astranull-control-plane:\$SHA"/);
    assert.match(deploy, /assert_image_identities_compatible/);
    assert.match(releaseState, /CURRENT_RELEASE_BUNDLE_FILE="\$DEPLOY_STATE_DIR\/release-image-current"/);
    assert.match(releaseState, /PENDING_RELEASE_BUNDLE_FILE="\$DEPLOY_STATE_DIR\/release-image-pending"/);
    assert.match(releaseState, /RELEASE_BUNDLE_SCHEMA=astranull\.release-image-bundle/);
    assert.match(releaseState, /os\.fsync\(source_fd\)[\s\S]*os\.fsync\(dir_fd\)[\s\S]*os\.replace\(source, destination\)[\s\S]*os\.fsync\(dir_fd\)/m);
    assert.match(releaseState, /reconcile_pending_release_bundle\(\)[\s\S]*release_runtime_matches_bundle_file[\s\S]*promote_pending_release_bundle/m);
    assert.match(releaseState, /Compatibility projections are never authoritative/);
    assert.match(deploy, /reconcile_pending_release_bundle[\s\S]*prepare_previous_release_images/m);

    const restoreScript = read('ops/aws/restore.sh');
    const deployRollbackCleanup = deploy.slice(deploy.indexOf('rollback_on_error()'), deploy.indexOf('handle_deploy_exit()'));
    const deploySuccessCleanup = deploy.match(/^finalize_success_cleanup\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    const restoreFailureCleanup = restoreScript.match(/^cleanup\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    for (const cleanup of [deployRollbackCleanup, deploySuccessCleanup, restoreFailureCleanup]) {
      assert.match(cleanup, /trap '' HUP INT TERM/);
    }

    const boundedPrune = deploy.match(/^bounded_prune_release_images\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(boundedPrune, /\^astranull-\(control-plane\|release-validator\):\(\[0-9a-f\]\{40\}\)\$/);
    assert.match(boundedPrune, /scan_count <= 256/);
    assert.match(boundedPrune, /remaining_count <= 11/);
    assert.match(boundedPrune, /CURRENT_RELEASE_BUNDLE_FILE[\s\S]*PENDING_RELEASE_BUNDLE_FILE[\s\S]*running_release_tag_refs/m);
    assert.doesNotMatch(deploy, /^\s*(?:timeout[^\n]*\s)?docker image prune\b/m);
  });

  it('creates encrypted backups and health-checks API, edge, workers, and rollback', () => {
    assert.match(deploy, /compose_ops_run 180 pg-dump[\s\S]*backup-dump[\s\S]*pg_dump[\s\S]*ASTRANULL_BACKUP_DATABASE_URL/m);
    assert.doesNotMatch(deploy, /exec -T postgres pg_dump|pg_dump -U astranull/);
    assert.match(deploy, /scripts\/postgres-backup\.mjs[\s\S]*--input[\s\S]*--database-host postgres --database-port 5432 --database-name astranull/m);
    assert.match(deploy, /\.dump\.enc/);
    assert.match(deploy, /tail -n \+11/);
    assert.match(deploy, /https:\/\/astranull\.site\/health/);
    assert.match(deploy, /probe-worker password-recovery-worker test-policy-runner/);
    assert.match(deploy, /check_control_plane/);
    assert.match(deploy, /postgres-restore-drill\.mjs[\s\S]*--validate-only/m);
    assert.match(deploy, /ASTRANULL_WORKER_IMAGE_TAG="\$previous_core_worker_tag"/);
    assert.match(deploy, /--rollback/);
    assert.match(deploy, /database was not downgraded/);

    const backupFunction = deploy.slice(deploy.indexOf('backup_database()'), deploy.indexOf('rollback_on_error()'));
    const bootstrapIndex = backupFunction.indexOf('backup-role-bootstrap');
    const dumpIndex = backupFunction.indexOf('backup-dump');
    const pgDumpIndex = backupFunction.indexOf('exec pg_dump');
    const structuralListIndex = backupFunction.indexOf('validate_plaintext_archive "$plain_host"');
    const encryptIndex = backupFunction.indexOf('postgres-backup.mjs');
    const validateIndex = backupFunction.indexOf('postgres-restore-drill.mjs');
    const validateOnlyIndex = backupFunction.indexOf('--validate-only');
    assert.ok(bootstrapIndex >= 0 && bootstrapIndex < dumpIndex && dumpIndex < pgDumpIndex);
    assert.ok(pgDumpIndex < structuralListIndex && structuralListIndex < encryptIndex);
    assert.ok(encryptIndex < validateIndex && validateIndex < validateOnlyIndex);
    assert.match(deploy, /validate_plaintext_archive\(\)[\s\S]*pg_restore --list/m);

    const inventoryFunction = deploy.match(/^list_valid_backup_artifacts\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(inventoryFunction, /artifacts\.length > 64/);
    assert.match(inventoryFunction, /\^postgres-\[A-Za-z0-9-\]\+-\[0-9a-f\]\{12\}/);
    assert.match(inventoryFunction, /validatePostgresBackupManifestFields\(manifest\)/);
    assert.match(inventoryFunction, /artifactStat\.nlink !== 1[\s\S]*manifestStat\.nlink !== 1/m);
    assert.match(inventoryFunction, /manifest\.backup_file !== name \|\| manifest\.bytes !== artifactStat\.size/);
    assert.match(inventoryFunction, /hash\.digest\("hex"\) !== manifest\.sha256/);
    assert.match(inventoryFunction, /throw new Error\(`backup encrypted digest mismatch/);
    assert.ok(deploy.indexOf('valid_artifacts=$(list_valid_backup_artifacts)') < deploy.indexOf('tail -n +11'));

    const targetMain = deploy.slice(deploy.lastIndexOf('\n  else\n'), deploy.indexOf('\n  finished=1'));
    assert.ok(targetMain.indexOf('backup_database') < targetMain.indexOf('compose_ops_run 180 migrate migrate'));
    assert.ok(targetMain.indexOf('compose_ops_run 180 migrate migrate') < targetMain.indexOf('start_core_stack'));
    assert.ok(targetMain.indexOf('backup_database') < targetMain.indexOf('activated=1'));

    const runbook = read('ops/aws/README.md');
    assert.match(runbook, /backup-dump[\s\S]*?ASTRANULL_BACKUP_DATABASE_URL[\s\S]*?postgres-backup\.mjs --input/m);
    assert.match(runbook, /--database-host postgres --database-port 5432 --database-name astranull/);
    assert.match(runbook, /`deploy\.sh` implements this exact handoff/);
  });

  it('separates owner migrations, backup reads, encryption, and enforced runtime roles', () => {
    const migration = compose.split('  migrate:')[1].split('\n  backup-role-bootstrap:')[0];
    const bootstrap = compose.split('  backup-role-bootstrap:')[1].split('\n  backup-dump:')[0];
    const dump = compose.split('  backup-dump:')[1].split('\n  restore-db:')[0];
    const restoreDatabase = compose.split('  restore-db:')[1].split('\n  backup:')[0];
    const encryption = compose.split('  backup:')[1].split('\n  control-plane:')[0];
    const control = compose.split('  control-plane:')[1].split('\n  probe-worker:')[0];
    const recovery = compose.split('  password-recovery-worker:')[1].split('\n  test-policy-runner:')[0];
    const policyScheduler = compose.split('  test-policy-runner:')[1].split('\n  connector-poll-scheduler:')[0];
    const connectorScheduler = compose.split('  connector-poll-scheduler:')[1].split('\n  connector-poll-runner:')[0];
    const connectorWorker = compose.split('  connector-poll-runner:')[1].split('\n  caddy:')[0];
    assert.match(migration, /profiles: \["ops"\]/);
    assert.match(migration, /postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
    assert.match(migration, /ASTRANULL_DATABASE_BACKUP_PASSWORD: \$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.match(migration, /migrate-postgres\.mjs && node scripts\/postgres-grant-app-role\.mjs/);
    assert.match(deploy, /compose_ops_run 180 migrate migrate/);

    assert.match(bootstrap, /ASTRANULL_ADMIN_DATABASE_URL: postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
    assert.match(bootstrap, /ASTRANULL_DATABASE_BACKUP_PASSWORD: \$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.match(bootstrap, /postgres-grant-app-role\.mjs", "--backup-only"/);
    assert.doesNotMatch(bootstrap, /DATABASE_APP_PASSWORD|BACKUP_ENCRYPTION_KEY|SECRET_ENCRYPTION_KEY/);
    assert.match(deploy, /compose_ops_run 90 backup-role-bootstrap backup-role-bootstrap/);

    assert.match(dump, /postgresql:\/\/astranull_backup:\$\{ASTRANULL_DATABASE_BACKUP_PASSWORD\}/);
    assert.doesNotMatch(dump, /POSTGRES_PASSWORD|DATABASE_APP_PASSWORD|BACKUP_ENCRYPTION_KEY|SECRET_ENCRYPTION_KEY/);
    assert.match(restoreDatabase, /profiles: \["ops"\]/);
    assert.match(restoreDatabase, /image: postgres:16-alpine@sha256:[0-9a-f]{64}/);
    assert.match(restoreDatabase, /ASTRANULL_MAINTENANCE_DATABASE_URL: postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}@postgres:5432\/postgres/);
    assert.match(restoreDatabase, /ASTRANULL_RESTORE_DATABASE_URL: postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}@postgres:5432\/astranull/);
    assert.doesNotMatch(restoreDatabase, /DATABASE_APP_PASSWORD|DATABASE_BACKUP_PASSWORD|BACKUP_ENCRYPTION_KEY|SECRET_ENCRYPTION_KEY|CONNECTOR/);
    assert.match(encryption, /ASTRANULL_BACKUP_ENCRYPTION_KEY/);
    assert.doesNotMatch(encryption, /DATABASE_URL|BACKUP_DATABASE_URL|DATABASE_APP_PASSWORD|DATABASE_BACKUP_PASSWORD|POSTGRES_PASSWORD|SECRET_ENCRYPTION_KEY/);

    for (const runtime of [control, recovery, policyScheduler]) {
      assert.match(runtime, /postgresql:\/\/astranull_app:/);
      assert.match(runtime, /ASTRANULL_ENFORCE_DATABASE_ROLE: "1"/);
      assert.doesNotMatch(runtime, /postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
      assert.doesNotMatch(runtime, /astranull_backup|ASTRANULL_DATABASE_BACKUP_PASSWORD/);
    }
    assert.match(connectorScheduler, /postgresql:\/\/astranull_connector_scheduler:\$\{ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD:-\}/);
    assert.match(connectorWorker, /postgresql:\/\/astranull_connector_worker:\$\{ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD:-\}/);
    for (const runtime of [connectorScheduler, connectorWorker]) {
      assert.match(runtime, /ASTRANULL_ENFORCE_DATABASE_ROLE: "1"/);
      assert.doesNotMatch(runtime, /postgresql:\/\/astranull_app:|postgresql:\/\/astranull:\$\{POSTGRES_PASSWORD\}/);
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
    const policyScheduler = compose.split('  test-policy-runner:')[1].split('\n  connector-poll-scheduler:')[0];
    const connectorScheduler = compose.split('  connector-poll-scheduler:')[1].split('\n  connector-poll-runner:')[0];
    const connectorWorker = compose.split('  connector-poll-runner:')[1].split('\n  caddy:')[0];
    for (const worker of [probe, recovery, policyScheduler, connectorScheduler, connectorWorker]) {
      assert.doesNotMatch(worker, /env_file:/);
      assert.match(worker, /healthcheck:/);
    }
    assert.match(probe, /command: \["node", "workers\/probe-worker\.mjs"\]/);
    assert.match(probe, /ASTRANULL_API_URL: http:\/\/control-plane:8080/);
    assert.doesNotMatch(probe, /DATABASE_URL|OIDC|SMTP|SECRET_ENCRYPTION/);
    assert.doesNotMatch(recovery, /OIDC|PROBE_WORKER_SECRET/);
    assert.doesNotMatch(policyScheduler, /OIDC|SMTP|SECRET_ENCRYPTION/);
    assert.match(connectorScheduler, /depends_on:\n\s+control-plane:\n\s+condition: service_healthy/);
    assert.match(connectorWorker, /depends_on:\n\s+control-plane:\n\s+condition: service_healthy/);
    assert.match(connectorScheduler, /--queue-only/);
    assert.match(connectorScheduler, /ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY/);
    assert.doesNotMatch(connectorScheduler, /ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY/);
    assert.match(connectorWorker, /ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY/);
    assert.doesNotMatch(connectorWorker, /ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY/);
    assert.doesNotMatch(connectorScheduler, /OIDC|PROBE_WORKER_SECRET|SECRET_ENCRYPTION_KEY|CONNECTOR_WORKER_ID/);
    assert.match(connectorWorker, /ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY/);
    assert.doesNotMatch(connectorWorker, /\n\s+ASTRANULL_SECRET_ENCRYPTION_KEY:/);
    assert.match(connectorWorker, /ASTRANULL_CONNECTOR_WORKER_ID/);
    assert.doesNotMatch(connectorWorker, /OIDC|PROBE_WORKER_SECRET|--queue-only/);
    for (const connectorWorkload of [connectorScheduler, connectorWorker]) {
      assert.match(connectorWorkload, /ASTRANULL_CONNECTOR_WORKER_IMAGE_ID/);
      assert.match(connectorWorkload, /ASTRANULL_WAF_POSTURE_ENABLED: \$\{ASTRANULL_WAF_POSTURE_ENABLED:-0\}/);
      assert.doesNotMatch(connectorWorkload, /ASTRANULL_WAF_POSTURE_ENABLED: "1"/);
      assert.match(connectorWorkload, /ASTRANULL_CONNECTORS_ENABLED/);
      assert.match(connectorWorkload, /ASTRANULL_CONNECTORS_ENABLED_TENANTS/);
      assert.match(connectorWorkload, /ASTRANULL_CONNECTOR_POLL_CONCURRENCY:-4/);
    }

    const connectorSchedulerTick = Number(connectorScheduler.match(
      /timeout -k 10 (\d+) node scripts\/connector-poll-runner\.mjs --queue-only/,
    )?.[1]);
    const connectorSchedulerSleep = Number(connectorScheduler.match(/"\$\$interval" -gt (\d+)/)?.[1]);
    const connectorSchedulerFreshness = Number(connectorScheduler.match(
      /connector-poll-scheduler\.heartbeat", "(\d+)"/,
    )?.[1]);
    assert.ok(connectorSchedulerSleep <= 60);
    assert.ok(connectorSchedulerFreshness - connectorSchedulerTick - connectorSchedulerSleep >= 30);

    const connectorWorkerTick = Number(connectorWorker.match(
      /timeout -k 10 (\d+) node scripts\/connector-poll-runner\.mjs/,
    )?.[1]);
    const connectorWorkerSleep = Number(connectorWorker.match(/"\$\$interval" -gt (\d+)/)?.[1]);
    const connectorWorkerFreshness = Number(connectorWorker.match(
      /connector-poll-runner\.heartbeat", "(\d+)"/,
    )?.[1]);
    assert.ok(connectorWorkerTick < 180);
    assert.ok(connectorWorkerSleep <= 60);
    assert.ok(connectorWorkerFreshness - connectorWorkerTick - connectorWorkerSleep >= 30);
    const runner = read('scripts/test-policy-runner.mjs');
    const envExample = read('ops/aws/env.example');
    assert.match(policyScheduler, /test-policy-runner\.heartbeat/);
    assert.match(policyScheduler, /worker-heartbeat-health\.mjs/);
    assert.match(policyScheduler, /restart: unless-stopped/);
    const intervalAssignment = policyScheduler.indexOf('interval=$${ASTRANULL_TEST_POLICY_INTERVAL_SECONDS:-30}');
    const intervalGuard = policyScheduler.indexOf("*[!0-9]*");
    const loop = policyScheduler.indexOf('while true');
    const sleep = policyScheduler.indexOf('sleep "$$interval"');
    assert.ok(intervalAssignment >= 0 && intervalGuard > intervalAssignment && loop > intervalGuard && sleep > loop);
    assert.match(policyScheduler, /"\$\$interval" -lt 5[\s\S]*?"\$\$interval" -gt 30/);
    assert.doesNotMatch(policyScheduler, /sleep \$\$\{ASTRANULL_TEST_POLICY_INTERVAL_SECONDS/);

    const boundedTick = policyScheduler.match(
      /if timeout -k 10 (\d+) node scripts\/test-policy-runner\.mjs; then([\s\S]*?)else([\s\S]*?)fi;/,
    );
    assert.ok(boundedTick, 'expected a bounded policy tick with explicit success and failure branches');
    const tickLimitSeconds = Number(boundedTick[1]);
    const maxSleepSeconds = Number(policyScheduler.match(/"\$\$interval" -gt (\d+)/)?.[1]);
    const freshnessSeconds = Number(policyScheduler.match(
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

  it('routes every AWS runtime removal through the verified stop-kill-rm helper', () => {
    const restoreScript = read('ops/aws/restore.sh');
    for (const [name, source] of [['deploy', deploy], ['restore', restoreScript]]) {
      const helper = source.match(/^stop_remove_services\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
      assert.match(helper, /compose_timeout 120 stop/);
      assert.match(helper, /compose_timeout 120 kill/);
      assert.match(helper, /compose_timeout 120 rm -f/);
      assert.match(helper, /verify_services_absent/);
      assert.equal((source.match(/compose_timeout 120 stop/g) ?? []).length, 1, `${name} has a direct stop outside the helper`);
      assert.equal((source.match(/compose_timeout 120 kill/g) ?? []).length, 1, `${name} has a direct kill outside the helper`);
      assert.equal((source.match(/compose_timeout 120 rm -f/g) ?? []).length, 1, `${name} has a direct rm outside the helper`);
      assert.doesNotMatch(source, /--remove-orphans/);
    }
    assert.match(deploy, /stop_connector_workers\(\) \{\n\s+stop_remove_services connector-poll-scheduler connector-poll-runner/);
    assert.match(deploy, /start_core_stack\(\) \{\n\s+stop_remove_services caddy control-plane probe-worker password-recovery-worker \\[\s\S]*test-policy-runner connector-poll-scheduler connector-poll-runner \|\| return/);
    assert.match(deploy, /fail_closed_runtime\(\) \{\n\s+stop_remove_services caddy/);
    assert.match(restoreScript, /start_core_stack\(\) \{\n\s+stop_remove_services caddy control-plane probe-worker password-recovery-worker \\[\s\S]*test-policy-runner connector-poll-scheduler connector-poll-runner \|\| return/);
    assert.match(restoreScript, /outage_started=1\n\s+stop_remove_services caddy/);
    assert.match(restoreScript, /! succeeded && outage_started[\s\S]*stop_remove_services caddy/m);
  });


  it('keeps direct AWS Compose runbook commands parseable with transient exact image IDs', () => {
    const runbook = read('ops/aws/README.md');
    const directComposeBlocks = [...runbook.matchAll(/```bash\n([\s\S]*?)```/g)]
      .map((match) => match[1])
      .filter((block) => block.includes('docker compose'));
    assert.ok(directComposeBlocks.length > 0);
    for (const block of directComposeBlocks) {
      const parsed = spawnSync('/bin/bash', ['-n'], { input: block, encoding: 'utf8' });
      assert.equal(parsed.status, 0, parsed.stderr);
      assert.match(block, /CURRENT_RELEASE_BUNDLE_FILE/);
      assert.match(block, /source ops\/aws\/release-state\.sh/);
      assert.match(block, /release_bundle_load "\$CURRENT_RELEASE_BUNDLE_FILE"/);
      assert.doesNotMatch(block, /control-plane-image-tag|core-worker-image-state|connector-image-state|release-validator-image-state/);
      assert.match(block, /ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=\$ASTRANULL_CORE_WORKER_IMAGE_ID/);
      assert.match(block, /export ASTRANULL_CONTROL_PLANE_IMAGE_ID[\s\S]*ASTRANULL_CORE_WORKER_IMAGE_ID[\s\S]*ASTRANULL_CONNECTOR_WORKER_IMAGE_ID/m);
      assert.match(block, /cleanup_compose_image_ids[\s\S]*unset ASTRANULL_CONTROL_PLANE_IMAGE_ID/m);
      assert.doesNotMatch(block, />>?\s*ops\/aws\/\.env/);
    }
  });

  it('keeps the AWS example connector-disabled with every connector secret blank', () => {
    const envExample = read('ops/aws/env.example');
    const runbook = read('ops/aws/README.md');
    assert.match(envExample, /^ASTRANULL_CONNECTORS_ENABLED=0$/m);
    for (const name of [
      'ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD',
      'ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD',
      'ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY',
      'ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY',
      'ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY',
    ]) {
      assert.match(envExample, new RegExp(`^${name}=$`, 'm'), `${name} must be blank by default`);
    }
    assert.match(envExample, /To enable connectors:[\s\S]*fill both connector DB passwords[\s\S]*set explicit tenant scope/);
    assert.match(runbook, /leave connector-only passwords\/keys\/encryption blank while connectors are disabled/);
    assert.match(runbook, /rendered connector mode must agree with canonical connector intent/);
  });

  it('validates before outage, restores into a clean database, and verifies exact runtime identities', () => {
    const restore = read('scripts/postgres-restore-drill.mjs');
    const runbook = read('ops/aws/README.md');
    const restoreScript = read('ops/aws/restore.sh');
    assert.match(restore, /--extract requires --yes/);
    assert.match(restore, /createWriteStream\(extractedTo, \{ flags: 'wx', mode: 0o600 \}\)/);
    assert.doesNotMatch(restore, /readFileSync/);
    assert.match(runbook, /ops\/aws\/restore\.sh --yes/);
    assert.match(restoreScript, /flock -n 9/);
    assert.match(restoreScript, /git status --porcelain --untracked-files=all/);
    assert.match(restoreScript, /CORE_WORKER_IMAGE_STATE_FILE="\$DEPLOY_STATE_DIR\/core-worker-image-state"/);
    assert.match(restoreScript, /RELEASE_VALIDATOR_IMAGE_STATE_FILE="\$DEPLOY_STATE_DIR\/release-validator-image-state"/);
    assert.match(restoreScript, /release_validator_tag=\$\(read_release_validator_image_tag\)/);
    assert.match(restoreScript, /release_validator_image_id=\$\(read_release_validator_image_id\)/);
    assert.match(restoreScript, /rebind_release_validator_image_tag/);
    assert.match(restoreScript, /core_worker_tag=\$\(read_core_worker_image_tag\)/);
    assert.match(restoreScript, /core_worker_image_id=\$\(read_core_worker_image_id\)/);
    assert.match(restoreScript, /rebind_control_plane_image_tag[\s\S]*rebind_core_worker_image_tag/m);
    assert.match(restoreScript, /ASTRANULL_IMAGE_TAG="\$core_worker_tag"/);
    assert.match(restoreScript, /ASTRANULL_WORKER_IMAGE_TAG="\$core_worker_tag"/);
    assert.match(restoreScript, /COMPOSE_SNAPSHOT_FILE="\$BACKUP_DIR\/\.astranull-compose-source\.restore\.\$\$"/);
    assert.match(restoreScript, /snapshot_compose_file\(\)[\s\S]*cat -- "\$COMPOSE_FILE" > "\$COMPOSE_SNAPSHOT_FILE"/m);
    assert.match(restoreScript, /-f "\$COMPOSE_SNAPSHOT_FILE" --env-file "\$ENV_SNAPSHOT"/);
    assert.doesNotMatch(restoreScript, /git rev-parse HEAD|worker_image_id=\$\(image_id_for_ref/);

    const connectorIntent = restoreScript.slice(
      restoreScript.indexOf('load_restore_connector_intent()'),
      restoreScript.indexOf('verify_service_image_tag()'),
    );
    assert.doesNotMatch(connectorIntent, /validate_compose|config --format json/);
    assert.match(connectorIntent, /disabled\)[\s\S]*connector_enabled=0[\s\S]*ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG="\$core_worker_tag"/m);
    assert.match(connectorIntent, /enabled\)[\s\S]*connector_image_state_exists[\s\S]*read_connector_image_tag[\s\S]*connector_image_supports_split_mode/m);
    assert.match(connectorIntent, /connectors are enabled but persisted connector state is missing/);

    assert.match(restoreScript, /verify_running_control_plane_state[\s\S]*verify_running_core_worker_state[\s\S]*verify_running_connector_state/m);
    assert.match(restoreScript, /verify_restored_image_identity/);
    assert.match(restoreScript, /restore: ok[^"\n]*core_ops_workers=astranull-control-plane:\$core_worker_tag@\$core_worker_image_id[^"\n]*release_validator=astranull-release-validator:\$release_validator_tag@\$release_validator_image_id/);
    assert.match(restoreScript, /compose_ops_run 90 restore-db-recreate -T restore-db/);
    assert.match(restoreScript, /timeout -k 10 75 psql --no-psqlrc --dbname="\$ASTRANULL_MAINTENANCE_DATABASE_URL" -v ON_ERROR_STOP=1/);
    assert.match(restoreScript, /DROP DATABASE IF EXISTS astranull WITH \(FORCE\)/);
    assert.match(restoreScript, /CREATE DATABASE astranull WITH OWNER astranull TEMPLATE template0/);
    assert.match(restoreScript, /compose_ops_run 600 restore-db-archive[\s\S]*-v "\$BACKUP_DIR:\/backup:ro" restore-db[\s\S]*timeout -k 30 540 pg_restore[\s\S]*--dbname="\$ASTRANULL_RESTORE_DATABASE_URL"[\s\S]*--single-transaction --exit-on-error --no-owner --no-acl/m);
    assert.doesNotMatch(restoreScript, /compose_timeout (?:90|600) exec -T postgres|pg_restore -U astranull/);
    assert.doesNotMatch(restoreScript, /exec[^\n]*pg_restore[^\n]*(?:\\\n[^\n]*){0,8}--clean/m);
    assert.doesNotMatch(restoreScript, /docker cp/);

    const archiveValidator = restoreScript.match(/^validate_plaintext_archive\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    const plaintextSecurity = restoreScript.match(/^restore_plaintext_file_security\(\) \{[\s\S]*?^\}/m)?.[0] ?? '';
    assert.match(archiveValidator, /restore_plaintext_file_security/);
    assert.match(plaintextSecurity, /-f "\$candidate" && ! -L "\$candidate"/);
    assert.match(plaintextSecurity, /link count/);
    assert.match(plaintextSecurity, /mode 0600/);
    assert.match(plaintextSecurity, /owned by the restore user/);
    assert.match(archiveValidator, /compose_ops_run 60 pg-restore-list[\s\S]*backup-dump[\s\S]*pg_restore --list/m);

    const cleanupPath = restoreScript.slice(
      restoreScript.indexOf('cleanup()'),
      restoreScript.indexOf('main()'),
    );
    assert.match(cleanupPath, /cleanup_active_operation_containers_checked[\s\S]*cleanup_compose_render_checked[\s\S]*delete_plaintext_checked "\$plain_host"/m);
    assert.match(cleanupPath, /cleanup_compose_snapshot_checked[\s\S]*cleanup_env_snapshot_checked/m);
    assert.match(cleanupPath, /! succeeded && outage_started[\s\S]*stop_remove_services caddy/m);
    assert.match(cleanupPath, /shutdown could not be verified; immediate operator intervention/);
    assert.match(cleanupPath, /preflight failed before outage; runtime services were not intentionally stopped/);

    const restoreMain = restoreScript.slice(restoreScript.indexOf('main()'));
    const snapshotCompose = restoreMain.indexOf('snapshot_compose_file');
    const loadIdentity = restoreMain.indexOf('load_restore_image_identity');
    const loadValidator = restoreMain.indexOf('load_release_validator_image_identity');
    const validateCompose = restoreMain.indexOf('validate_compose "$release_validator_image_id" connector_mode');
    const loadConnector = restoreMain.indexOf('load_restore_connector_intent');
    const verifyRunning = restoreMain.indexOf('verify_running_control_plane_state');
    const drill = restoreMain.indexOf('postgres-restore-drill.mjs');
    const extract = restoreMain.indexOf('--extract', drill);
    const structuralList = restoreMain.indexOf('validate_plaintext_archive "$plain_host"');
    const outage = restoreMain.indexOf('outage_started=1');
    const shutdown = restoreMain.indexOf('stop_remove_services caddy', outage);
    const drop = restoreMain.indexOf('compose_ops_run 90 restore-db-recreate');
    const restoreArchive = restoreMain.indexOf('compose_ops_run 600 restore-db-archive');
    const removePlaintext = restoreMain.indexOf('delete_plaintext_checked "$plain_host"', restoreArchive);
    const migrate = restoreMain.indexOf('compose_ops_run 180 migrate migrate');
    const activate = restoreMain.indexOf('start_core_stack');
    const activateConnectors = restoreMain.indexOf('start_connector_workers');
    assert.ok(snapshotCompose >= 0 && snapshotCompose < loadIdentity);
    assert.ok(loadIdentity < loadValidator && loadValidator < validateCompose);
    assert.ok(validateCompose < loadConnector && loadConnector < verifyRunning);
    assert.ok(verifyRunning < drill && drill < extract && extract < structuralList && structuralList < outage);
    assert.ok(outage < shutdown && shutdown < drop && drop < restoreArchive);
    assert.ok(restoreArchive < removePlaintext && removePlaintext < migrate && migrate < activate);
    assert.ok(activate < activateConnectors, 'restore must verify core before starting enabled connectors');
    assert.equal((restoreMain.match(/postgres-restore-drill\.mjs/g) ?? []).length, 1);
    assert.equal((restoreMain.match(/--extract/g) ?? []).length, 1);
    assert.doesNotMatch(restoreMain, /--validate-only/);
  });

  it('matches src/config connector default and tenant-map parsing exactly', () => {
    for (const [raw, expected] of [
      [undefined, false], [null, false], ['', false], ['   ', false],
      ['0', false], [0, false], ['1', true], [1, true],
    ]) {
      assert.equal(
        connectorWorkloadsEnabled({ ASTRANULL_CONNECTORS_ENABLED: raw }),
        expected,
        `default ${String(raw)} should resolve to ${expected}`,
      );
    }
    for (const raw of ['true', 'false', 'yes', 'on', '01', '2', true, false]) {
      assert.throws(
        () => connectorWorkloadsEnabled({ ASTRANULL_CONNECTORS_ENABLED: raw }),
        /must be 1 or 0/,
        `default ${String(raw)} must fail`,
      );
    }
    for (const [raw, expected] of [
      [undefined, false], [null, false], ['', false], ['   ', false],
      ['0', false], [0, false], ['1', true], [1, true],
    ]) {
      assert.equal(
        wafPostureEnabled({ ASTRANULL_WAF_POSTURE_ENABLED: raw }),
        expected,
        `WAF flag ${String(raw)} should resolve to ${expected}`,
      );
    }
    for (const raw of ['true', 'false', 'yes', 'on', '01', '2', true, false]) {
      assert.throws(
        () => wafPostureEnabled({ ASTRANULL_WAF_POSTURE_ENABLED: raw }),
        /must be 1 or 0/,
        `WAF flag ${String(raw)} must fail`,
      );
    }

    for (const [raw, expected] of [
      ['', false], ['{}', false],
      ['{"a":false,"b":0,"c":"0"}', false],
      ['{"a":true,"b":1,"c":"1","d":false,"e":0,"f":"0"}', true],
      ['{" tenant ":true}', true],
      ['{"tenant":true," tenant ":false}', false],
      ['{"tenant":false," tenant ":true}', true],
    ]) {
      assert.equal(
        connectorWorkloadsEnabled({
          ASTRANULL_CONNECTORS_ENABLED: '0',
          ASTRANULL_CONNECTORS_ENABLED_TENANTS: raw,
        }),
        expected,
        `tenant map ${raw} should resolve to ${expected}`,
      );
    }
    for (const raw of [
      '{', '[]', 'null', '{" ":true}', '{"a":"true"}', '{"a":"false"}',
      '{"a":2}', '{"a":-1}', '{"a":null}', '{"a":{}}', '{"a":[]}',
    ]) {
      assert.throws(
        () => connectorWorkloadsEnabled({
          ASTRANULL_CONNECTORS_ENABLED: '0',
          ASTRANULL_CONNECTORS_ENABLED_TENANTS: raw,
        }),
        /tenant|JSON|boolean|0\/1/i,
        `tenant map ${raw} must fail`,
      );
    }
  });

  it('rejects eight-way credential reuse, supports disabled connectors, and preserves service boundaries', () => {
    const owner = 'a'.repeat(64);
    const app = 'b'.repeat(64);
    const backupDb = 'c'.repeat(64);
    const backupEncryption = 'd'.repeat(64);
    const envelopeEncryption = 'e'.repeat(64);
    const connectorEncryption = 'f1'.repeat(32);
    const connectorSchedulerDb = '1a'.repeat(32);
    const connectorWorkerDb = '2b'.repeat(32);
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const connectorJobPrivateKey = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
    const connectorJobPublicKey = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const probeWorkerSecret = '12'.repeat(24);
    const model = {
      services: {
        postgres: { environment: { POSTGRES_PASSWORD: owner } },
        migrate: { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
          ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
          ASTRANULL_DATABASE_APP_PASSWORD: app,
          ASTRANULL_DATABASE_BACKUP_PASSWORD: backupDb,
          ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD: connectorSchedulerDb,
          ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD: connectorWorkerDb,
        } },
        'backup-role-bootstrap': { environment: {
          NODE_ENV: 'production',
          ASTRANULL_ADMIN_DATABASE_URL: `postgresql://astranull:${owner}@postgres/astranull`,
          ASTRANULL_DATABASE_BACKUP_PASSWORD: backupDb,
        } },
        'backup-dump': { environment: {
          ASTRANULL_BACKUP_DATABASE_URL: `postgresql://astranull_backup:${backupDb}@postgres/astranull`,
        } },
        'restore-db': { environment: {
          ASTRANULL_MAINTENANCE_DATABASE_URL: `postgresql://astranull:${owner}@postgres:5432/postgres`,
          ASTRANULL_RESTORE_DATABASE_URL: `postgresql://astranull:${owner}@postgres:5432/astranull`,
        } },
        backup: { environment: {
          NODE_ENV: 'production',
          ASTRANULL_BACKUP_ENCRYPTION_KEY: backupEncryption,
        } },
        'control-plane': { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull_app:${app}@postgres/astranull`,
          ASTRANULL_SECRET_ENCRYPTION_KEY: envelopeEncryption,
          ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY: connectorEncryption,
          ASTRANULL_PROBE_WORKER_SECRET: probeWorkerSecret,
          ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY: connectorJobPrivateKey,
          ASTRANULL_WAF_POSTURE_ENABLED: '1',
          ASTRANULL_CONNECTORS_ENABLED: '1',
        } },
        'probe-worker': { environment: {} },
        'password-recovery-worker': { environment: {
          ASTRANULL_SECRET_ENCRYPTION_KEY: envelopeEncryption,
        } },
        'test-policy-runner': { environment: {} },
        'connector-poll-scheduler': { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull_connector_scheduler:${connectorSchedulerDb}@postgres/astranull`,
          ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY: connectorJobPrivateKey,
          ASTRANULL_WAF_POSTURE_ENABLED: '1',
        } },
        'connector-poll-runner': { environment: {
          ASTRANULL_DATABASE_URL: `postgresql://astranull_connector_worker:${connectorWorkerDb}@postgres/astranull`,
          ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY: connectorJobPublicKey,
          ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY: connectorEncryption,
          ASTRANULL_WAF_POSTURE_ENABLED: '1',
        } },
      },
    };
    const controlServiceImage = `sha256:${'1c'.repeat(32)}`;
    const coreServiceImage = `sha256:${'2d'.repeat(32)}`;
    const connectorServiceImage = `sha256:${'3e'.repeat(32)}`;
    model.services['control-plane'].image = controlServiceImage;
    for (const name of [
      'migrate', 'backup-role-bootstrap', 'backup', 'probe-worker',
      'password-recovery-worker', 'test-policy-runner',
    ]) model.services[name].image = coreServiceImage;
    for (const name of ['connector-poll-scheduler', 'connector-poll-runner']) {
      model.services[name].image = connectorServiceImage;
    }
    assert.equal(validateAwsComposeSecretModel(model), true);
    assert.equal(validatedAwsComposeConnectorMode(model), 'enabled');

    const taggedImageModel = structuredClone(model);
    taggedImageModel.services['control-plane'].image = 'astranull-control-plane:mutable';
    assert.throws(() => validateAwsComposeSecretModel(taggedImageModel), /full local sha256 image ID/);
    const splitCoreImageModel = structuredClone(model);
    splitCoreImageModel.services.backup.image = `sha256:${'4f'.repeat(32)}`;
    assert.throws(() => validateAwsComposeSecretModel(splitCoreImageModel), /core image group/);
    const wrongRestoreOwnerModel = structuredClone(model);
    wrongRestoreOwnerModel.services['restore-db'].environment.ASTRANULL_RESTORE_DATABASE_URL =
      `postgresql://astranull:${app}@postgres:5432/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(wrongRestoreOwnerModel), /exact owner URL/);
    const projectedRestoreSecretModel = structuredClone(model);
    projectedRestoreSecretModel.services['restore-db'].environment.ASTRANULL_BACKUP_ENCRYPTION_KEY = backupEncryption;
    assert.throws(() => validateAwsComposeSecretModel(projectedRestoreSecretModel), /may receive only exact owner/);

    const invalidDefaultModel = structuredClone(model);
    invalidDefaultModel.services['control-plane'].environment.ASTRANULL_CONNECTORS_ENABLED = 'true';
    assert.throws(() => validatedAwsComposeConnectorMode(invalidDefaultModel), /must be 1 or 0/);
    const invalidDefaultCli = spawnSync(
      process.execPath,
      [path.join(ROOT, 'scripts/validate-aws-compose-secrets.mjs'), '--print-connector-mode'],
      { input: JSON.stringify(invalidDefaultModel), encoding: 'utf8' },
    );
    assert.notEqual(invalidDefaultCli.status, 0);
    assert.equal(invalidDefaultCli.stdout, '');
    assert.match(invalidDefaultCli.stderr, /must be 1 or 0/);

    const disabledModel = structuredClone(model);
    disabledModel.services['control-plane'].environment.ASTRANULL_CONNECTORS_ENABLED = '0';
    disabledModel.services['control-plane'].environment.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY = '';
    disabledModel.services['control-plane'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = '';
    disabledModel.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD = '';
    disabledModel.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD = '';
    disabledModel.services['connector-poll-scheduler'].environment.ASTRANULL_DATABASE_URL =
      'postgresql://astranull_connector_scheduler:@postgres/astranull';
    disabledModel.services['connector-poll-scheduler'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = '';
    disabledModel.services['connector-poll-runner'].environment.ASTRANULL_DATABASE_URL =
      'postgresql://astranull_connector_worker:@postgres/astranull';
    disabledModel.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = '';
    disabledModel.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY = '';
    assert.equal(validateAwsComposeSecretModel(disabledModel), true);
    assert.equal(validatedAwsComposeConnectorMode(disabledModel), 'disabled');
    disabledModel.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = connectorJobPublicKey;
    assert.throws(() => validateAwsComposeSecretModel(disabledModel), /must not project connector credentials/);
    assert.throws(() => validatedAwsComposeConnectorMode(disabledModel), /must not project connector credentials/);
    disabledModel.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = '';
    const disabledCredentialProjections = [
      (candidate) => { candidate.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD = connectorSchedulerDb; },
      (candidate) => { candidate.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD = connectorWorkerDb; },
      (candidate) => { candidate.services['control-plane'].environment.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY = connectorEncryption; },
      (candidate) => { candidate.services['control-plane'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = connectorJobPrivateKey; },
      (candidate) => { candidate.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = connectorJobPublicKey; },
    ];
    for (const projectCredential of disabledCredentialProjections) {
      const candidate = structuredClone(disabledModel);
      projectCredential(candidate);
      assert.throws(() => validateAwsComposeSecretModel(candidate));
      assert.throws(() => validatedAwsComposeConnectorMode(candidate));
    }

    for (const connectorsEnabled of [false, true]) {
      for (let bits = 0; bits < 8; bits += 1) {
        const candidate = structuredClone(connectorsEnabled ? model : disabledModel);
        candidate.services['control-plane'].environment.ASTRANULL_CONNECTORS_ENABLED = connectorsEnabled ? '1' : '0';
        const flags = [
          (bits & 4) === 0 ? '0' : '1',
          (bits & 2) === 0 ? '0' : '1',
          (bits & 1) === 0 ? '0' : '1',
        ];
        candidate.services['control-plane'].environment.ASTRANULL_WAF_POSTURE_ENABLED = flags[0];
        candidate.services['connector-poll-scheduler'].environment.ASTRANULL_WAF_POSTURE_ENABLED = flags[1];
        candidate.services['connector-poll-runner'].environment.ASTRANULL_WAF_POSTURE_ENABLED = flags[2];
        const allMatch = new Set(flags).size === 1;
        const valid = allMatch && (!connectorsEnabled || flags[0] === '1');
        if (valid) {
          assert.equal(validateAwsComposeSecretModel(candidate), true);
          assert.equal(
            validatedAwsComposeConnectorMode(candidate),
            connectorsEnabled ? 'enabled' : 'disabled',
          );
        } else {
          assert.throws(
            () => validateAwsComposeSecretModel(candidate),
            allMatch ? /connectors cannot be enabled while WAF posture is disabled/ : /must match across/,
            `connectors=${connectorsEnabled} WAF=${flags.join('/')}`,
          );
        }
      }
    }

    const blankConnectorCredentials = [
      (candidate) => { candidate.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD = ''; },
      (candidate) => { candidate.services.migrate.environment.ASTRANULL_DATABASE_CONNECTOR_WORKER_PASSWORD = ''; },
      (candidate) => { candidate.services['control-plane'].environment.ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY = ''; },
      (candidate) => { candidate.services['control-plane'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = ''; },
      (candidate) => { candidate.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = ''; },
    ];
    for (const blank of blankConnectorCredentials) {
      const candidate = structuredClone(model);
      blank(candidate);
      assert.throws(() => validateAwsComposeSecretModel(candidate));
      assert.throws(() => validatedAwsComposeConnectorMode(candidate));
    }

    model.services.postgres.environment.POSTGRES_PASSWORD = 'f'.repeat(64);
    assert.throws(() => validateAwsComposeSecretModel(model), /owner passwords must match/);
    model.services.postgres.environment.POSTGRES_PASSWORD = owner;

    model.services.migrate.environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = app;
    model.services['backup-role-bootstrap'].environment.ASTRANULL_DATABASE_BACKUP_PASSWORD = app;
    model.services['backup-dump'].environment.ASTRANULL_BACKUP_DATABASE_URL = `postgresql://astranull_backup:${app}@postgres/astranull`;
    assert.throws(() => validateAwsComposeSecretModel(model), /distinct secret/);
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
    delete model.services['backup-dump'].environment.ASTRANULL_BACKUP_ENCRYPTION_KEY;

    model.services['control-plane'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = '<generate Ed25519 PKCS8>';
    model.services['connector-poll-scheduler'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = '<generate Ed25519 PKCS8>';
    assert.throws(() => validateAwsComposeSecretModel(model), /Ed25519 PKCS8/);
    model.services['control-plane'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = connectorJobPrivateKey;
    model.services['connector-poll-scheduler'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = connectorJobPrivateKey;

    const otherPublicKey = generateKeyPairSync('ed25519').publicKey
      .export({ format: 'der', type: 'spki' }).toString('base64');
    model.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = otherPublicKey;
    assert.throws(() => validateAwsComposeSecretModel(model), /matching Ed25519 keypair/);
    model.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY = connectorJobPublicKey;

    model.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY = connectorJobPrivateKey;
    assert.throws(() => validateAwsComposeSecretModel(model), /private key must be signer-only/);
    delete model.services['connector-poll-runner'].environment.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY;

    model.services['connector-poll-scheduler'].environment.ASTRANULL_SECRET_ENCRYPTION_KEY = envelopeEncryption;
    assert.throws(() => validateAwsComposeSecretModel(model), /scheduler has an unexpected environment field/);
    delete model.services['connector-poll-scheduler'].environment.ASTRANULL_SECRET_ENCRYPTION_KEY;

    model.services['connector-poll-runner'].environment.ASTRANULL_PROBE_WORKER_SECRET = probeWorkerSecret;
    assert.throws(() => validateAwsComposeSecretModel(model), /worker has an unexpected environment field/);
    delete model.services['connector-poll-runner'].environment.ASTRANULL_PROBE_WORKER_SECRET;
  });

  it('prints no connector mode when CLI validation fails', () => {
    const result = spawnSync(
      process.execPath,
      [path.join(ROOT, 'scripts/validate-aws-compose-secrets.mjs'), '--print-connector-mode'],
      { input: '{}', encoding: 'utf8' },
    );
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /missing postgres service/);
  });

  it('makes deploy artifact parsing a prerequisite of CI success', () => {
    assert.match(ci, /bash -n ops\/aws\/deploy\.sh/);
    assert.match(ci, /bash -n ops\/aws\/restore\.sh/);
    assert.match(ci, /validate-aws-compose-secrets\.mjs/);
    assert.match(ci, /docker compose[\s\S]*config --no-interpolate --no-path-resolution/m);
    assert.match(ci, /docker build -f ops\/aws\/Dockerfile -t astranull-ci-check/);
  });
});
