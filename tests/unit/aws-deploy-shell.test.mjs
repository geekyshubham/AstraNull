import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEPLOY = path.join(ROOT, 'ops/aws/deploy.sh');
const RESTORE = path.join(ROOT, 'ops/aws/restore.sh');
const PROCESS_GROUP_WATCHDOG = String.raw`
import os
import signal
import subprocess
import sys

proc = subprocess.Popen(sys.argv[1:], start_new_session=True)
try:
    rc = proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    print('watchdog: shell reproduction timed out after 5s', file=sys.stderr)
    sys.exit(124)
sys.exit(128 + -rc if rc < 0 else rc)
`;

function runBash(source, env = {}, script = DEPLOY) {
  const result = spawnSync(
    'python3',
    ['-c', PROCESS_GROUP_WATCHDOG, '/bin/bash', '-c', source, 'aws-source-test', script],
    {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, ...env },
      timeout: 7_000,
      killSignal: 'SIGKILL',
    },
  );
  assert.notEqual(result.error?.code, 'ETIMEDOUT', 'Python process-group watchdog itself stalled');
  return result;
}

function writeFakeTimeout(directory) {
  const executable = path.join(directory, 'timeout');
  writeFileSync(executable, `#!/usr/bin/env bash
set -euo pipefail
if [[ \${1:-} == -k ]]; then shift 2; fi
shift
exec "$@"
`);
  chmodSync(executable, 0o755);
}

describe('AWS deploy shell lifecycle', () => {
  it('is sourceable without running deployment main', () => {
    const result = runBash('source "$1"; declare -F main ensure_postgres_ready_for_backup install_failure_traps >/dev/null; printf source-ok');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'source-ok');
  });

  it('preserves status 130 through signal and EXIT rollback traps', () => {
    const rollbackSetup = `
      previous_compose=/tmp/astranull-source-test.previous.yml
      target_compose=/tmp/astranull-source-test.target.yml
      plain_host=''
      plain_container=''
      previous=${'b'.repeat(40)}
      previous_control_plane_tag=${'c'.repeat(40)}
      previous_control_plane_image_id=sha256:${'d'.repeat(64)}
      backup=''
      activated=0
      migration_started=0
      finished=0
      git() { return 0; }
      rebind_control_plane_image_tag() { return 0; }
      cleanup_compose_snapshots() { return 0; }
      install_failure_traps
    `;

    const signaled = runBash(`source "$1"\n${rollbackSetup}\nkill -TERM $$`);
    assert.equal(signaled.status, 130, signaled.stderr);
    assert.match(signaled.stderr, /failed before service activation/);

    const exited = runBash(`source "$1"\n${rollbackSetup}\nexit 130`);
    assert.equal(exited.status, 130, exited.stderr);
    assert.match(exited.stderr, /failed before service activation/);
  });

  it('returns failure for either control-plane check under set +e, conditionals, and negation', () => {
    for (const [internalRc, externalRc] of [[41, 0], [0, 42]]) {
      const result = runBash(`
        source "$1"
        compose_timeout() { return "$INTERNAL_RC"; }
        curl() { return "$EXTERNAL_RC"; }

        set +e
        check_control_plane
        direct_rc=$?
        set -e
        (( direct_rc != 0 )) || exit 91
        if check_control_plane; then exit 92; fi
        if ! check_control_plane; then printf failure-propagated; else exit 93; fi
      `, { INTERNAL_RC: String(internalRc), EXTERNAL_RC: String(externalRc) });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'failure-propagated');
    }
  });

  it('bootstraps only a genuinely fresh postgres and health-checks it', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-deploy-shell-'));
    try {
      const freshLog = path.join(temp, 'fresh.log');
      const fresh = runBash(`
        source "$1"
        started=0
        compose_timeout() {
          printf '%s\\n' "$*" >> "$CALL_LOG"
          if [[ "$*" == '30 ps --all -q postgres' && ( "$SCENARIO" == existing || "$started" == 1 ) ]]; then
            printf container-id
          elif [[ "$*" == '180 up -d --no-deps --wait --wait-timeout 120 postgres' ]]; then
            started=1
          fi
        }
        postgres_volume_name() { printf aws_pgdata; }
        docker_volume_exists() { [[ "$SCENARIO" == stale-volume ]]; }
        ensure_postgres_ready_for_backup
      `, { CALL_LOG: freshLog, SCENARIO: 'fresh' });
      assert.equal(fresh.status, 0, fresh.stderr);
      const freshCalls = readFileSync(freshLog, 'utf8').trim().split('\n');
      assert.deepEqual(freshCalls, [
        '30 ps --all -q postgres',
        '180 up -d --no-deps --wait --wait-timeout 120 postgres',
        '30 ps --all -q postgres',
        '30 exec -T postgres pg_isready -U astranull -d astranull',
      ]);

      const existingLog = path.join(temp, 'existing.log');
      const existing = runBash(`
        source "$1"
        compose_timeout() {
          printf '%s\\n' "$*" >> "$CALL_LOG"
          [[ "$*" != '30 ps --all -q postgres' ]] || printf container-id
        }
        postgres_volume_name() { return 99; }
        docker_volume_exists() { return 99; }
        ensure_postgres_ready_for_backup
      `, { CALL_LOG: existingLog });
      assert.equal(existing.status, 0, existing.stderr);
      assert.deepEqual(readFileSync(existingLog, 'utf8').trim().split('\n'), [
        '30 ps --all -q postgres',
        '30 exec -T postgres pg_isready -U astranull -d astranull',
      ]);

      const staleVolume = runBash(`
        source "$1"
        compose_timeout() {
          if [[ "$*" == '30 ps --all -q postgres' ]]; then return 0; fi
        }
        postgres_volume_name() { printf aws_pgdata; }
        docker_volume_exists() { return 0; }
        ensure_postgres_ready_for_backup
      `);
      assert.equal(staleVolume.status, 1);
      assert.match(staleVolume.stderr, /exists without a service container/);

      const unknownVolumeState = runBash(`
        source "$1"
        compose_timeout() {
          if [[ "$*" == '30 ps --all -q postgres' ]]; then return 0; fi
        }
        postgres_volume_name() { printf aws_pgdata; }
        docker_volume_exists() { return 2; }
        ensure_postgres_ready_for_backup
      `);
      assert.equal(unknownVolumeState.status, 1);
      assert.match(unknownVolumeState.stderr, /could not verify whether postgres data volume/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('preserves the exact running image across the historical build-only first upgrade', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-legacy-image-'));
    const oldTag = 'a'.repeat(40);
    const actualImageId = `sha256:${'1'.repeat(64)}`;
    const fakeDocker = path.join(temp, 'docker');
    const aliasFile = path.join(temp, 'alias-id');
    const callLog = path.join(temp, 'docker.log');
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$1" == inspect && "$3" == '{{.Image}}' && "$4" == legacy-control-plane ]]; then
  printf '%s\\n' "$ACTUAL_IMAGE_ID"
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ "$3" == "$ACTUAL_IMAGE_ID" && "$4" == "astranull-control-plane:$OLD_TAG" ]]
  printf '%s\\n' "$3" > "$ALIAS_FILE"
elif [[ "$1 $2" == 'image inspect' && "$5" == "astranull-control-plane:$OLD_TAG" ]]; then
  cat "$ALIAS_FILE"
else
  exit 97
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
        compose_timeout() {
          [[ "$*" == '30 ps --all -q control-plane' ]] && printf legacy-control-plane
        }
        prepare_previous_control_plane_image "$OLD_TAG"
        printf '%s' "$previous_control_plane_image_id"
      `, {
        ACTUAL_IMAGE_ID: actualImageId,
        ALIAS_FILE: aliasFile,
        FAKE_DOCKER_LOG: callLog,
        OLD_TAG: oldTag,
        PATH: `${temp}:${process.env.PATH}`,
        STATE_DIR: path.join(temp, 'state'),
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, actualImageId);
      assert.equal(readFileSync(aliasFile, 'utf8').trim(), actualImageId);
      assert.match(readFileSync(callLog, 'utf8'), new RegExp(`image tag ${actualImageId} astranull-control-plane:${oldTag}`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('uses tested target orchestration for automatic hybrid rollback from legacy Compose', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-hybrid-rollback-'));
    const legacyCompose = path.join(temp, 'legacy.yml');
    const targetCompose = path.join(temp, 'target.yml');
    const callLog = path.join(temp, 'calls.log');
    const oldTag = 'b'.repeat(40);
    const targetTag = 'c'.repeat(40);
    writeFileSync(legacyCompose, 'services:\n  control-plane:\n    build:\n      context: ../..\n  caddy:\n    image: caddy\n');
    writeFileSync(targetCompose, 'services:\n  control-plane:\n    image: astranull-control-plane:${ASTRANULL_CONTROL_PLANE_IMAGE_TAG}\n  probe-worker: {}\n  password-recovery-worker: {}\n  test-policy-runner: {}\n');
    assert.doesNotMatch(readFileSync(legacyCompose, 'utf8'), /probe-worker|password-recovery-worker|test-policy-runner|control-plane:\n\s+image:/);

    try {
      const result = runBash(`
        source "$1"
        MODE=deploy
        previous="$OLD_TAG"
        SHA="$TARGET_TAG"
        previous_control_plane_tag="$OLD_TAG"
        previous_control_plane_image_id="$OLD_IMAGE_ID"
        previous_compose="$LEGACY_COMPOSE"
        target_compose="$TARGET_COMPOSE"
        plain_host=''
        plain_container=''
        backup=/safe/predeploy.dump.enc
        activated=1
        migration_started=1
        cleanup_compose_snapshots() { :; }
        git() { printf 'git|%s\\n' "$*" >> "$CALL_LOG"; }
        compose_timeout() { printf 'compose|%s|%s|%s|%s|%s\\n' "$ACTIVE_COMPOSE_FILE" "$ASTRANULL_CONTROL_PLANE_IMAGE_TAG" "$ASTRANULL_WORKER_IMAGE_TAG" "$ASTRANULL_IMAGE_TAG" "$*" >> "$CALL_LOG"; }
        check_control_plane() { printf 'control-health|%s\\n' "$ACTIVE_COMPOSE_FILE" >> "$CALL_LOG"; }
        check_workers() { printf 'worker-health|%s\\n' "$ACTIVE_COMPOSE_FILE" >> "$CALL_LOG"; }
        rebind_control_plane_image_tag() { printf 'rebind|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        verify_control_plane_image_tag() { printf 'verify-control|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        verify_workers_image_tag() { printf 'verify-workers|%s\\n' "$1" >> "$CALL_LOG"; }
        persist_control_plane_image_state() { printf 'persist|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        rollback_on_error 73
      `, {
        CALL_LOG: callLog,
        LEGACY_COMPOSE: legacyCompose,
        OLD_IMAGE_ID: `sha256:${'2'.repeat(64)}`,
        OLD_TAG: oldTag,
        TARGET_COMPOSE: targetCompose,
        TARGET_TAG: targetTag,
      });
      assert.equal(result.status, 73, result.stderr);
      assert.match(result.stderr, new RegExp(`control-plane ${oldTag}@sha256:${'2'.repeat(64)} with orchestration/workers ${targetTag}`));
      assert.match(result.stderr, /database was not downgraded/);
      const calls = readFileSync(callLog, 'utf8');
      assert.match(calls, new RegExp(`git\\|checkout -q --detach ${targetTag}`));
      assert.match(calls, new RegExp(`rebind\\|${oldTag}\\|sha256:${'2'.repeat(64)}`));
      assert.match(calls, new RegExp(`compose\\|${targetCompose.replaceAll('/', '\\/')}\\|${oldTag}\\|${targetTag}\\|${targetTag}\\|300 up -d`));
      assert.ok(calls.indexOf('rebind|') < calls.indexOf('compose|'), 'rollback must rebind before Compose activation');
      assert.match(calls, new RegExp(`control-health\\|${targetCompose.replaceAll('/', '\\/')}`));
      assert.match(calls, new RegExp(`worker-health\\|${targetCompose.replaceAll('/', '\\/')}`));
      assert.doesNotMatch(calls, new RegExp(`compose\\|${legacyCompose.replaceAll('/', '\\/')}\\|`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rebinds a clobbered same-SHA tag to the captured image ID before automatic rollback', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-same-sha-rollback-'));
    const fakeDocker = path.join(temp, 'docker');
    const tagFile = path.join(temp, 'tag-image-id');
    const containerFile = path.join(temp, 'container-image-id');
    const callLog = path.join(temp, 'docker.log');
    const oldImageId = `sha256:${'a'.repeat(64)}`;
    const rebuiltImageId = `sha256:${'b'.repeat(64)}`;
    const sameSha = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$1" == build ]]; then
  cat >/dev/null
  printf '%s\n' "$REBUILT_IMAGE_ID" > "$TAG_FILE"
elif [[ "$1 $2" == 'image inspect' ]]; then
  if [[ "$5" == "$OLD_IMAGE_ID" ]]; then printf '%s\n' "$OLD_IMAGE_ID";
  elif [[ "$5" == "astranull-control-plane:$SAME_SHA" ]]; then cat "$TAG_FILE";
  else exit 91; fi
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ "$3" == "$OLD_IMAGE_ID" && "$4" == "astranull-control-plane:$SAME_SHA" ]]
  printf '%s\n' "$OLD_IMAGE_ID" > "$TAG_FILE"
elif [[ "$1" == inspect && "$3" == '{{.Config.Image}}' && "$4" == control-cid ]]; then
  printf 'astranull-control-plane:%s\n' "$SAME_SHA"
elif [[ "$1" == inspect && "$3" == '{{.Image}}' && "$4" == control-cid ]]; then
  cat "$CONTAINER_FILE"
else
  exit 92
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        same_sha=$(git rev-parse HEAD)
        DEPLOY_STATE_DIR="$STATE_DIR"
        CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
        persist_control_plane_image_state "$same_sha" "$OLD_IMAGE_ID"
        printf '%s\n' "$OLD_IMAGE_ID" > "$TAG_FILE"
        build_control_plane_from_commit "$same_sha"
        [[ "$(cat "$TAG_FILE")" == "$REBUILT_IMAGE_ID" ]] || exit 93

        MODE=deploy
        previous="$same_sha"
        SHA="$same_sha"
        previous_control_plane_tag="$same_sha"
        previous_control_plane_image_id="$OLD_IMAGE_ID"
        previous_compose="$DUMMY_COMPOSE"
        target_compose="$DUMMY_COMPOSE"
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        migration_started=1
        cleanup_compose_snapshots() { :; }
        git() { [[ "$*" == "checkout -q --detach $same_sha" ]]; }
        compose_timeout() {
          if [[ "$*" == '300 up -d --remove-orphans --wait --wait-timeout 240' ]]; then
            cat "$TAG_FILE" > "$CONTAINER_FILE"
          elif [[ "$*" == '30 ps -q control-plane' ]]; then
            printf control-cid
          else
            return 94
          fi
        }
        check_control_plane() { :; }
        check_workers() { :; }
        verify_workers_image_tag() { [[ "$1" == "$same_sha" ]]; }
        rollback_on_error 73
      `, {
        CONTAINER_FILE: containerFile,
        DUMMY_COMPOSE: path.join(temp, 'compose.yml'),
        FAKE_DOCKER_LOG: callLog,
        OLD_IMAGE_ID: oldImageId,
        PATH: `${temp}:${process.env.PATH}`,
        REBUILT_IMAGE_ID: rebuiltImageId,
        SAME_SHA: sameSha,
        STATE_DIR: path.join(temp, 'state'),
        TAG_FILE: tagFile,
      });
      assert.equal(result.status, 73, result.stderr);
      assert.match(result.stderr, /automatic hybrid rollback restored control-plane/);
      assert.equal(readFileSync(tagFile, 'utf8').trim(), oldImageId);
      assert.equal(readFileSync(containerFile, 'utf8').trim(), oldImageId);
      assert.equal(readFileSync(path.join(temp, 'state/control-plane-image-tag'), 'utf8'), `${sameSha}\n${oldImageId}\n`);
      const calls = readFileSync(callLog, 'utf8');
      assert.match(calls, /build -f ops\/aws\/Dockerfile -t astranull-control-plane:[0-9a-f]{40} -/);
      assert.match(calls, new RegExp(`image tag ${oldImageId} astranull-control-plane:[0-9a-f]{40}`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('feeds a real git archive tar to docker build stdin without a Docker daemon', (t) => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-archive-build-'));
    const fakeDocker = path.join(temp, 'docker');
    const argsFile = path.join(temp, 'args');
    const tarList = path.join(temp, 'tar-list');
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$@" > "$FAKE_DOCKER_ARGS"
[[ "$1" == build && "\${!#}" == - ]]
tar -tf - > "$FAKE_DOCKER_TAR_LIST"
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        tested_sha=$(git rev-parse HEAD)
        build_control_plane_from_commit "$tested_sha"
        printf 'tested-sha=%s' "$tested_sha"
      `, {
        FAKE_DOCKER_ARGS: argsFile,
        FAKE_DOCKER_TAR_LIST: tarList,
        PATH: `${temp}:${process.env.PATH}`,
      });
      assert.equal(result.status, 0, result.stderr);
      const testedSha = result.stdout.replace('tested-sha=', '');
      assert.match(testedSha, /^[0-9a-f]{40}$/);
      assert.deepEqual(readFileSync(argsFile, 'utf8').trim().split('\n'), [
        'build',
        '-f',
        'ops/aws/Dockerfile',
        '-t',
        `astranull-control-plane:${testedSha}`,
        '-',
      ]);
      const entries = readFileSync(tarList, 'utf8').trim().split('\n');
      assert.ok(entries.includes('package.json'));
      assert.ok(entries.includes('ops/aws/Dockerfile'));

      const releaseIndex = new Set(readFileSync(path.join(ROOT, 'ops/aws/release-archive-inputs.txt'), 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')));
      const dockerfile = readFileSync(path.join(ROOT, 'ops/aws/Dockerfile'), 'utf8');
      const copySources = dockerfile.split('\n')
        .filter((line) => line.startsWith('COPY '))
        .flatMap((line) => {
          const fields = line.trim().split(/\s+/).slice(1);
          while (fields[0]?.startsWith('--')) fields.shift();
          return fields.slice(0, -1);
        });
      for (const source of copySources) {
        assert.ok(releaseIndex.has(source), `Dockerfile COPY source ${source} must be in the release archive index`);
      }

      const criticalRuntimeInputs = [
        'scripts/worker-heartbeat-health.mjs',
        'THIRD_PARTY_NOTICES/cdncheck-MIT.txt',
        'THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt',
      ];
      for (const input of criticalRuntimeInputs) {
        assert.ok(releaseIndex.has(input), `${input} must be explicitly indexed`);
      }

      const archiveHas = (input) => entries.includes(input) || entries.some((entry) => entry.startsWith(`${input}/`));
      for (const input of releaseIndex) {
        if (archiveHas(input)) continue;
        const worktreePath = path.join(ROOT, input);
        assert.ok(existsSync(worktreePath), `${input} is absent from both the exact HEAD archive and worktree`);
        const indexed = spawnSync('git', ['ls-files', '--cached', '--error-unmatch', '--', input], {
          cwd: ROOT,
          encoding: 'utf8',
        });
        assert.equal(
          indexed.status,
          0,
          `${input} is absent from the exact HEAD archive and final candidate index; stage it before release validation`,
        );
        t.diagnostic(`${input} is present in the final candidate index and MUST remain in the aggregate commit before exact-SHA deployment`);
      }
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('atomically persists the hybrid control-plane tag and immutable ID outside the checkout', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-deploy-state-'));
    const tag = 'a'.repeat(40);
    const imageId = `sha256:${'5'.repeat(64)}`;
    try {
      const result = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
        persist_control_plane_image_state "$EXPECTED_TAG" "$EXPECTED_IMAGE_ID"
        printf '%s|%s' "$(read_control_plane_image_tag "${'b'.repeat(40)}")" "$(read_control_plane_image_id)"
      `, { STATE_DIR: temp, EXPECTED_IMAGE_ID: imageId, EXPECTED_TAG: tag });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `${tag}|${imageId}`);
      const stateFile = path.join(temp, 'control-plane-image-tag');
      assert.equal(readFileSync(stateFile, 'utf8'), `${tag}\n${imageId}\n`);
      assert.equal(statSync(stateFile).mode & 0o777, 0o600);
      assert.equal(statSync(temp).mode & 0o777, 0o700);
      assert.equal(stateFile.startsWith(ROOT), false);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});

describe('AWS restore image identity', () => {
  it('loads persisted control-plane state, keeps current workers, and verifies the hybrid runtime', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-identity-'));
    const persistedTag = 'd'.repeat(40);
    const currentTag = 'e'.repeat(40);
    const controlImageId = `sha256:${'3'.repeat(64)}`;
    const workerImageId = `sha256:${'4'.repeat(64)}`;
    const stateFile = path.join(temp, 'control-plane-image-tag');
    const fakeDocker = path.join(temp, 'docker');
    writeFileSync(stateFile, `${persistedTag}\n${controlImageId}\n`, { mode: 0o600 });
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'image inspect' ]]; then
  if [[ "$5" == "$CONTROL_IMAGE_ID" || "$5" == "astranull-control-plane:$PERSISTED_TAG" ]]; then printf '%s\\n' "$CONTROL_IMAGE_ID";
  elif [[ "$5" == "astranull-control-plane:$CURRENT_TAG" ]]; then printf '%s\\n' "$WORKER_IMAGE_ID";
  else exit 81; fi
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ "$3" == "$CONTROL_IMAGE_ID" && "$4" == "astranull-control-plane:$PERSISTED_TAG" ]]
elif [[ "$1" == inspect && "$3" == '{{.Config.Image}}' ]]; then
  if [[ "$4" == control-cid ]]; then printf 'astranull-control-plane:%s\\n' "$PERSISTED_TAG";
  else printf 'astranull-control-plane:%s\\n' "$CURRENT_TAG"; fi
elif [[ "$1" == inspect && "$3" == '{{.Image}}' ]]; then
  if [[ "$4" == control-cid ]]; then printf '%s\\n' "$CONTROL_IMAGE_ID";
  else printf '%s\\n' "$WORKER_IMAGE_ID"; fi
else
  exit 82
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_FILE"
        git() { [[ "$*" == 'rev-parse HEAD' ]] && printf '%s\\n' "$CURRENT_TAG"; }
        compose_timeout() {
          case "$*" in
            '30 ps -q control-plane') printf control-cid ;;
            '30 ps -q probe-worker') printf probe-cid ;;
            '30 ps -q password-recovery-worker') printf recovery-cid ;;
            '30 ps -q test-policy-runner') printf policy-cid ;;
            *) return 89 ;;
          esac
        }
        load_restore_image_identity
        verify_restored_image_identity
        printf '%s|%s|%s|%s|%s' "$control_plane_tag" "$orchestration_tag" "$ASTRANULL_CONTROL_PLANE_IMAGE_TAG" "$ASTRANULL_WORKER_IMAGE_TAG" "$ASTRANULL_IMAGE_TAG"
      `, {
        CONTROL_IMAGE_ID: controlImageId,
        CURRENT_TAG: currentTag,
        PATH: `${temp}:${process.env.PATH}`,
        PERSISTED_TAG: persistedTag,
        STATE_FILE: stateFile,
        WORKER_IMAGE_ID: workerImageId,
      }, RESTORE);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `${persistedTag}|${currentTag}|${persistedTag}|${currentTag}|${currentTag}`);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('repairs a stopped same-SHA stack from the persisted ID before loading worker identity', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-stopped-'));
    const sameTag = '9'.repeat(40);
    const expectedImageId = `sha256:${'c'.repeat(64)}`;
    const clobberedImageId = `sha256:${'d'.repeat(64)}`;
    const stateFile = path.join(temp, 'control-plane-image-tag');
    const tagFile = path.join(temp, 'tag-image-id');
    const callLog = path.join(temp, 'docker.log');
    const fakeDocker = path.join(temp, 'docker');
    writeFileSync(stateFile, `${sameTag}\n${expectedImageId}\n`, { mode: 0o600 });
    writeFileSync(tagFile, `${clobberedImageId}\n`);
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$1 $2" == 'image inspect' ]]; then
  if [[ "$5" == "$EXPECTED_IMAGE_ID" ]]; then printf '%s\n' "$EXPECTED_IMAGE_ID";
  elif [[ "$5" == "astranull-control-plane:$SAME_TAG" ]]; then cat "$TAG_FILE";
  else exit 95; fi
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ "$3" == "$EXPECTED_IMAGE_ID" && "$4" == "astranull-control-plane:$SAME_TAG" ]]
  printf '%s\n' "$EXPECTED_IMAGE_ID" > "$TAG_FILE"
else
  exit 96
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_FILE"
        git() { [[ "$*" == 'rev-parse HEAD' ]] && printf '%s\n' "$SAME_TAG"; }
        compose_timeout() { [[ "$*" == '30 ps -q control-plane' ]]; }
        load_restore_image_identity
        verify_running_control_plane_state
        printf '%s|%s' "$control_plane_image_id" "$worker_image_id"
      `, {
        EXPECTED_IMAGE_ID: expectedImageId,
        FAKE_DOCKER_LOG: callLog,
        PATH: `${temp}:${process.env.PATH}`,
        SAME_TAG: sameTag,
        STATE_FILE: stateFile,
        TAG_FILE: tagFile,
      }, RESTORE);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `${expectedImageId}|${expectedImageId}`);
      assert.equal(readFileSync(tagFile, 'utf8').trim(), expectedImageId);
      assert.match(readFileSync(callLog, 'utf8'), new RegExp(`image tag ${expectedImageId} astranull-control-plane:${sameTag}`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('fails closed for a stopped stack when the persisted image ID is missing', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-missing-image-'));
    const tag = '1'.repeat(40);
    const expectedImageId = `sha256:${'e'.repeat(64)}`;
    const mutableImageId = `sha256:${'f'.repeat(64)}`;
    const stateFile = path.join(temp, 'control-plane-image-tag');
    const fakeDocker = path.join(temp, 'docker');
    const callLog = path.join(temp, 'docker.log');
    writeFileSync(stateFile, `${tag}\n${expectedImageId}\n`, { mode: 0o600 });
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$1 $2" == 'image inspect' && "$5" == "$EXPECTED_IMAGE_ID" ]]; then exit 1; fi
if [[ "$1 $2" == 'image inspect' && "$5" == "astranull-control-plane:$TAG" ]]; then printf '%s\n' "$MUTABLE_IMAGE_ID"; exit 0; fi
exit 97
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_FILE"
        git() { [[ "$*" == 'rev-parse HEAD' ]] && printf '%s\n' "$TAG"; }
        load_restore_image_identity
      `, {
        EXPECTED_IMAGE_ID: expectedImageId,
        FAKE_DOCKER_LOG: callLog,
        MUTABLE_IMAGE_ID: mutableImageId,
        PATH: `${temp}:${process.env.PATH}`,
        STATE_FILE: stateFile,
        TAG: tag,
      }, RESTORE);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /expected control-plane image .* is unavailable/);
      assert.doesNotMatch(readFileSync(callLog, 'utf8'), /image tag/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rejects persisted state that does not match the running control-plane identity', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-stale-state-'));
    const persistedTag = '6'.repeat(40);
    const runningTag = '7'.repeat(40);
    const imageId = `sha256:${'8'.repeat(64)}`;
    const fakeDocker = path.join(temp, 'docker');
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == inspect && "$3" == '{{.Config.Image}}' ]]; then
  printf 'astranull-control-plane:%s\\n' "$RUNNING_TAG"
elif [[ "$1" == inspect && "$3" == '{{.Image}}' ]]; then
  printf '%s\\n' "$IMAGE_ID"
else
  exit 83
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        control_plane_tag="$PERSISTED_TAG"
        control_plane_image_id="$IMAGE_ID"
        compose_timeout() { [[ "$*" == '30 ps -q control-plane' ]] && printf control-cid; }
        verify_running_control_plane_state
      `, {
        IMAGE_ID: imageId,
        PATH: `${temp}:${process.env.PATH}`,
        PERSISTED_TAG: persistedTag,
        RUNNING_TAG: runningTag,
      }, RESTORE);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /control-plane uses unexpected image/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});
