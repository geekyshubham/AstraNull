import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { after, describe, it } from 'node:test';
import {
  ARTIFACT_TYPE,
  BACKUP_ENCRYPTION_ALGORITHM,
  BACKUP_ENVELOPE_VERSION,
  MANIFEST_VERSION,
  classifyPostgresBackupArtifactName,
} from '../../scripts/postgres-backup.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SHELL_BACKUP_DIR = mkdtempSync(path.join(tmpdir(), 'astranull-shell-backups-'));
chmodSync(SHELL_BACKUP_DIR, 0o700);
after(() => rmSync(SHELL_BACKUP_DIR, { recursive: true, force: true }));
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
      env: { ...process.env, ASTRANULL_TEST_BACKUP_DIR: SHELL_BACKUP_DIR, ...env },
      timeout: 7_000,
      killSignal: 'SIGKILL',
    },
  );
  assert.notEqual(result.error?.code, 'ETIMEDOUT', 'Python process-group watchdog itself stalled');
  return result;
}

function runLocalBackupInventory(backupDir, body, env = {}) {
  return runBash(`
    source "$1"
    ROOT="$REPO_ROOT_FIXTURE"
    BACKUP_DIR="$BACKUP_DIR_FIXTURE"
    timeout() {
      if [[ \${1:-} == -k ]]; then shift 2; fi
      shift
      "$@"
    }
    compose_ops_run() {
      shift 2
      while (( $# > 0 )) && [[ "$1" != node ]]; do shift; done
      (( $# > 0 )) || return 97
      local args=("$@") last
      last=$((\${#args[@]} - 1))
      args[$last]="$BACKUP_DIR_FIXTURE"
      command "\${args[@]}"
    }
    ${body}
  `, { BACKUP_DIR_FIXTURE: backupDir, REPO_ROOT_FIXTURE: ROOT, ...env });
}

function writeInventoryBackupPair(directory, name, manifestOverrides = {}) {
  const bytes = Buffer.from('encrypted-backup');
  writeFileSync(path.join(directory, name), bytes, { mode: 0o600 });
  writeFileSync(path.join(directory, `${name}.manifest.json`), `${JSON.stringify({
    version: MANIFEST_VERSION,
    artifact_type: ARTIFACT_TYPE,
    created_at: '2026-08-31T12:00:00.000Z',
    backup_file: name,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.length,
    label: null,
    database_reference: { host: 'postgres', port: 5432, database: 'astranull' },
    dump_format: 'pg_custom',
    encryption: {
      algorithm: BACKUP_ENCRYPTION_ALGORITHM,
      key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
      envelope_version: BACKUP_ENVELOPE_VERSION,
    },
    ...manifestOverrides,
  }, null, 2)}\n`, { mode: 0o600 });
}

function backupIdentityRecord(directory, name, recordName = name) {
  const fields = (target) => {
    const value = statSync(target, { bigint: true });
    return [
      value.dev, value.ino, value.size, value.mtimeNs, value.ctimeNs,
      value.mode, value.uid, value.gid, value.nlink,
    ].map(String);
  };
  return [
    recordName,
    ...fields(path.join(directory, name)),
    ...fields(path.join(directory, `${name}.manifest.json`)),
  ].join('\t');
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

function writeFakeContainerNodeRunner(directory) {
  const fakeDocker = path.join(directory, 'docker');
  const fakeNode = path.join(directory, 'node');
  const dockerLog = path.join(directory, 'docker.log');
  const hostNodeLog = path.join(directory, 'host-node.log');
  const containerState = path.join(directory, 'container-name');
  writeFakeTimeout(directory);
  writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
state_file=${JSON.stringify(containerState)}
if [[ "$1 $2" == 'container ls' ]]; then
  [[ ! -f "$state_file" ]] || cat "$state_file"
  exit 0
fi
if [[ "$1 $2" == 'rm -f' ]]; then
  [[ "$3" == -- && "\${4}" == "$(cat "$state_file")" ]] || exit 95
  rm -f "$state_file"
  exit 0
fi
[[ "$1" == run && "$2" == --name && -n "$3" && "$4" == --network && "$5" == none \
  && "$6" == --read-only && "$7" == --user && "$8" == 10001:10001 && "$9" == -i \
  && "\${10}" == "$EXPECTED_IMAGE_ID" && "\${11}" == node ]] || exit 90
printf '%s' "$3" > "$state_file"
payload=$(cat)
[[ "$payload" == "$EXPECTED_COMPOSE_JSON" ]] || exit 91
printf '%s|%s|%s\n' "\${10}" "\${11}" "\${12}" >> "$FAKE_DOCKER_LOG"
case "\${12}" in
  scripts/validate-aws-compose-secrets.mjs)
    [[ $# == 13 && "\${13}" == --print-connector-mode ]] || exit 92
    printf '%s\n' "\${FAKE_VALIDATOR_OUTPUT:-$EXPECTED_CONNECTOR_MODE}"
    ;;
  -e)
    [[ $# == 13 ]] || exit 93
    printf 'aws_pgdata'
    ;;
  *) exit 94 ;;
esac
`);
  writeFileSync(fakeNode, `#!/usr/bin/env bash
printf 'host node invoked: %s\n' "$*" >> "$HOST_NODE_LOG"
exit 99
`);
  chmodSync(fakeDocker, 0o755);
  chmodSync(fakeNode, 0o755);
  return { containerState, dockerLog, hostNodeLog };
}

describe('AWS deploy shell lifecycle', () => {
  it('is sourceable without running deployment main', () => {
    const result = runBash('source "$1"; declare -F main ensure_postgres_ready_for_backup install_failure_traps >/dev/null; printf source-ok');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'source-ok');
  });

  it('keeps the shell cleanup predicate aligned with exact Node current classification', () => {
    const current = 'postgres-2026-08-30T16-47-04-492Z-abcdef123456.dump.enc';
    const cases = [
      [current, 'current'],
      ['postgres-2024-02-29T23-59-59-999Z-abcdef123456.dump.enc', 'current'],
      ['postgres-2026-08-30T16-47-04-492Z.dump.enc', 'legacy'],
      ['postgres-2000-02-29T00-00-00-000Z.dump.enc', 'legacy'],
      ['postgres-2026-00-15T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-13-15T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-01-00T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-04-31T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2025-02-29T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2024-02-30T12-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-08-30T24-00-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-60-00-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-47-60-000Z-abcdef123456.dump.enc', 'unknown'],
      ['postgres-2025-02-29T12-00-00-000Z.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-47-04-492Z-ABCDEF123456.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-47-04-492Z-abcdef12345.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-47-04-492Z-abcdef1234567.dump.enc', 'unknown'],
      ['postgres-2026-08-30T16-47-04Z-abcdef123456.dump.enc', 'unknown'],
      [`${current}\n`, 'unknown'],
      [`postgres-2026-08-30T16-47-04-492Z-abc\ndef123456.dump.enc`, 'unknown'],
      [`../${current}`, 'unknown'],
      [`/backup/${current}`, 'unknown'],
      [`backup\\${current}`, 'unknown'],
    ];
    for (const [name, expected] of cases) {
      assert.equal(classifyPostgresBackupArtifactName(name), expected, JSON.stringify(name));
      const shell = runBash(`
        source "$1"
        if is_current_backup_artifact_name "$CANDIDATE"; then printf current; else printf not-current; fi
      `, { CANDIDATE: name });
      assert.equal(shell.status, 0, shell.stderr);
      assert.equal(shell.stdout, expected === 'current' ? 'current' : 'not-current', JSON.stringify(name));
    }
  });

  it('rejects a symlinked private deploy lock and never mutates its target', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-lock-safety-`));
      const backupDir = path.join(temp, 'backups');
      const victim = path.join(temp, 'victim');
      mkdirSync(backupDir, { mode: 0o700 });
      writeFileSync(victim, 'unchanged', { mode: 0o600 });
      symlinkSync(victim, path.join(backupDir, 'deploy.lock'));
      try {
        const result = runBash('source "$1"; acquire_deploy_lock', {
          ASTRANULL_TEST_BACKUP_DIR: backupDir,
        }, script);
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /unsafe deployment lock path/);
        assert.equal(readFileSync(victim, 'utf8'), 'unchanged');
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('sweeps only bounded stale deploy and restore operation containers under the shared lock', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-stale-ops-`));
      const state = path.join(temp, 'containers');
      const fakeDocker = path.join(temp, 'docker');
      mkdirSync(state);
      for (const container of ['astranull-deploy-backup-encrypt-111', 'astranull-restore-restore-db-222', 'unrelated-service']) {
        writeFileSync(path.join(state, container), container);
      }
      writeFakeTimeout(temp);
      writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'container ls' ]]; then
  for file in "$STALE_STATE"/*; do [[ ! -f "$file" ]] || cat "$file"; printf '\\n'; done
  exit 0
fi
if [[ "$1 $2" == 'rm -f' && "$3" == -- ]]; then rm -f -- "$STALE_STATE/$4"; exit 0; fi
exit 91
`);
      chmodSync(fakeDocker, 0o755);
      try {
        const result = runBash('source "$1"; cleanup_stale_operation_containers_checked', {
          PATH: `${temp}:${process.env.PATH}`,
          STALE_STATE: state,
        }, script);
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(readdirSync(state), ['unrelated-service']);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('deploy cleanup removes only allocator-exact scratch basenames and preserves collisions', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-deploy-scratch-collisions-'));
    const backupDir = path.join(temp, 'backups');
    mkdirSync(backupDir, { mode: 0o700 });
    const current = 'postgres-2026-08-31T12-00-00-000Z-abcdef123456.dump.enc';
    const exactScratch = [
      '.astranull-env.deploy.Ab3xY9',
      '.astranull-env.restore.z9Y8x7',
      '.astranull-plaintext.deploy.A1b2C3',
      '.astranull-plaintext.restore.d4E5f6',
      '.astranull-build-iid.G7h8I9',
      '.astranull-compose.previous.J1k2L3.yml',
      '.astranull-compose.target.m4N5o6.yml',
      '.astranull-compose-render.deploy.12345',
      '.astranull-compose-render.restore.67890',
      '.astranull-compose-source.restore.24680',
      `.${current}.partial-artifact-${'a'.repeat(24)}`,
      `.${current}.partial-manifest-${'b'.repeat(24)}`,
    ];
    const collisions = [
      '.postgres-operator.partial-copy.dump.enc',
      '.astranull-plaintext.deploy.operator.dump.enc',
      '.astranull-env.deploy.operator.dump.enc',
      '.astranull-env.deploy.Ab3xY',
      '.astranull-env.restore.Ab3xY90',
      '.astranull-plaintext.restore.Ab3_x9',
      '.astranull-build-iid.operator',
      '.astranull-compose.previous.operator.yml',
      '.astranull-compose-render.deploy.123.dump.enc',
      '.astranull-compose-render.deploy.0',
      '.astranull-compose-source.restore.0123',
      '.astranull-compose-source.restore.operator',
      `.postgres-2026-02-30T12-00-00-000Z-abcdef123456.dump.enc.partial-artifact-${'c'.repeat(24)}`,
      `.${current}.partial-artifact-${'D'.repeat(24)}`,
      current,
      `${current}.manifest.json`,
    ];
    try {
      for (const name of [...exactScratch, ...collisions]) {
        writeFileSync(path.join(backupDir, name), `content:${name}`, { mode: 0o600 });
      }
      const preservedDirectory = path.join(backupDir, '.astranull-env.restore.operator.dump.enc');
      const victim = path.join(backupDir, 'victim');
      const preservedSymlink = path.join(backupDir, '.astranull-plaintext.restore.operator.dump.enc');
      mkdirSync(preservedDirectory);
      writeFileSync(victim, 'victim', { mode: 0o600 });
      symlinkSync(victim, preservedSymlink);

      const result = runBash(
        'source "$1"; cleanup_stale_release_workspace; cleanup_backup_orphans',
        { ASTRANULL_TEST_BACKUP_DIR: backupDir },
      );
      assert.equal(result.status, 0, result.stderr);
      for (const name of exactScratch) assert.equal(existsSync(path.join(backupDir, name)), false, name);
      for (const name of collisions) assert.equal(existsSync(path.join(backupDir, name)), true, name);
      assert.equal(existsSync(preservedDirectory), true);
      assert.equal(existsSync(preservedSymlink), true);
      assert.equal(readFileSync(victim, 'utf8'), 'victim');

      const inventory = runLocalBackupInventory(backupDir, 'list_valid_backup_artifacts');
      assert.notEqual(inventory.status, 0);
      assert.match(inventory.stderr, /unsafe backup artifact name/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('restore cleanup removes exact allocator scratch basenames and preserves collisions', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-scratch-collisions-'));
    const backupDir = path.join(temp, 'backups');
    mkdirSync(backupDir, { mode: 0o700 });
    const exactScratch = [
      '.astranull-env.deploy.Ab3xY9',
      '.astranull-env.restore.z9Y8x7',
      '.astranull-plaintext.deploy.A1b2C3',
      '.astranull-plaintext.restore.d4E5f6',
      '.astranull-build-iid.G7h8I9',
      '.astranull-compose.previous.J1k2L3.yml',
      '.astranull-compose.target.m4N5o6.yml',
      '.astranull-compose-render.deploy.12345',
      '.astranull-compose-render.restore.67890',
      '.astranull-compose-source.restore.24680',
    ];
    const collisions = [
      '.astranull-env.deploy.operator.dump.enc',
      '.astranull-plaintext.restore.operator.dump.enc',
      '.astranull-env.deploy.Ab3xY',
      '.astranull-plaintext.deploy.A1b2C34',
      '.astranull-build-iid.operator',
      '.astranull-compose.target.operator.yml',
      '.astranull-compose-render.restore.operator',
      '.astranull-compose-render.restore.0',
      '.astranull-compose-source.restore.0123',
      '.astranull-compose-source.restore.123.dump.enc',
    ];
    try {
      for (const name of [...exactScratch, ...collisions]) {
        writeFileSync(path.join(backupDir, name), `content:${name}`, { mode: 0o600 });
      }
      const preservedDirectory = path.join(backupDir, '.astranull-env.restore.operator.dump.enc');
      const victim = path.join(backupDir, 'victim');
      const preservedSymlink = path.join(backupDir, '.astranull-plaintext.deploy.operator-link.dump.enc');
      mkdirSync(preservedDirectory);
      writeFileSync(victim, 'victim', { mode: 0o600 });
      symlinkSync(victim, preservedSymlink);

      const result = runBash(
        'source "$1"; cleanup_stale_release_workspace; cleanup_stale_plaintext_archives',
        { ASTRANULL_TEST_BACKUP_DIR: backupDir },
        RESTORE,
      );
      assert.equal(result.status, 0, result.stderr);
      for (const name of exactScratch) assert.equal(existsSync(path.join(backupDir, name)), false, name);
      for (const name of collisions) assert.equal(existsSync(path.join(backupDir, name)), true, name);
      assert.equal(existsSync(preservedDirectory), true);
      assert.equal(existsSync(preservedSymlink), true);
      assert.equal(readFileSync(victim, 'utf8'), 'victim');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('parses Compose JSON through a locked-down exact-image runner, never host node', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-release-node-'));
    const imageId = `sha256:${'7'.repeat(64)}`;
    const composeJson = '{"volumes":{"pgdata":{"name":"aws_pgdata"}}}';
    const { dockerLog, hostNodeLog } = writeFakeContainerNodeRunner(temp);
    try {
      const result = runBash(`
        source "$1"
        compose_timeout() {
          case "$*" in
            '30 --profile ops config --format json'|'30 config --format json') printf '%s' "$EXPECTED_COMPOSE_JSON" ;;
            *) return 88 ;;
          esac
        }
        validate_compose "$EXPECTED_IMAGE_ID" connector_mode
        printf '%s\nvolume=%s' "$connector_mode" "$(postgres_volume_name "$EXPECTED_IMAGE_ID")"
      `, {
        EXPECTED_COMPOSE_JSON: composeJson,
        EXPECTED_IMAGE_ID: imageId,
        FAKE_DOCKER_LOG: dockerLog,
        HOST_NODE_LOG: hostNodeLog,
        EXPECTED_CONNECTOR_MODE: 'disabled',
        PATH: `${temp}:${process.env.PATH}`,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'disabled\nvolume=aws_pgdata');
      assert.deepEqual(readFileSync(dockerLog, 'utf8').trim().split('\n'), [
        `${imageId}|node|scripts/validate-aws-compose-secrets.mjs`,
        `${imageId}|node|-e`,
      ]);
      assert.equal(existsSync(hostNodeLog), false);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('renders Compose exactly once for each validated connector-mode decision', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-one-render-`));
      const imageId = `sha256:${'6'.repeat(64)}`;
      const renderLog = path.join(temp, 'renders.log');
      const { dockerLog, hostNodeLog } = writeFakeContainerNodeRunner(temp);
      try {
        const result = runBash(`
          source "$1"
          compose_timeout() {
            printf '%s\\n' "$*" >> "$RENDER_LOG"
            printf '%s' "$EXPECTED_COMPOSE_JSON"
          }
          validate_compose "$EXPECTED_IMAGE_ID" mode
          printf '%s' "$mode"
        `, {
          EXPECTED_COMPOSE_JSON: '{"services":{}}',
          EXPECTED_CONNECTOR_MODE: 'enabled',
          EXPECTED_IMAGE_ID: imageId,
          FAKE_DOCKER_LOG: dockerLog,
          HOST_NODE_LOG: hostNodeLog,
          PATH: `${temp}:${process.env.PATH}`,
          RENDER_LOG: renderLog,
        }, script);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout, 'enabled');
        assert.equal(readFileSync(renderLog, 'utf8'), '30 --profile ops config --format json\n');
        assert.equal(readFileSync(dockerLog, 'utf8').trim(), `${imageId}|node|scripts/validate-aws-compose-secrets.mjs`);
        assert.equal(existsSync(hostNodeLog), false);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('rejects the legacy validator success token without any compatibility fallback', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-legacy-validator-rejected-`));
      const imageId = `sha256:${'6'.repeat(64)}`;
      const renderLog = path.join(temp, 'renders.log');
      const { dockerLog, hostNodeLog } = writeFakeContainerNodeRunner(temp);
      try {
        const result = runBash(`
          source "$1"
          compose_timeout() {
            printf '%s\\n' "$*" >> "$RENDER_LOG"
            printf '%s' "$EXPECTED_COMPOSE_JSON"
          }
          set +e
          validate_compose "$EXPECTED_IMAGE_ID" mode
          rc=$?
          set -e
          printf '%s|%s|%s' "$rc" "\${mode:-unset}" "$COMPOSE_RENDER_FILE"
        `, {
          EXPECTED_COMPOSE_JSON: '{"services":{}}',
          EXPECTED_CONNECTOR_MODE: 'unused-modern-mode',
          EXPECTED_IMAGE_ID: imageId,
          FAKE_DOCKER_LOG: dockerLog,
          FAKE_VALIDATOR_OUTPUT: 'aws-compose-secrets: ok',
          HOST_NODE_LOG: hostNodeLog,
          PATH: `${temp}:${process.env.PATH}`,
          RENDER_LOG: renderLog,
        }, script);
        assert.equal(result.status, 0, result.stderr);
        const [rc, mode, renderFile] = result.stdout.split('|');
        assert.notEqual(rc, '0');
        assert.equal(mode, 'unset');
        assert.equal(existsSync(renderFile), false, `${name} must remove the private render`);
        assert.equal(readFileSync(renderLog, 'utf8'), '30 --profile ops config --format json\n');
        assert.equal(
          readFileSync(dockerLog, 'utf8').trim(),
          `${imageId}|node|scripts/validate-aws-compose-secrets.mjs`,
        );
        assert.match(result.stderr, /current release-image Compose validator returned an unexpected result/);
        assert.equal(existsSync(hostNodeLog), false);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('accepts only exact enabled or disabled current validator output', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      for (const output of ['', ' enabled', 'enabled ', 'ok', 'enabled\ndisabled']) {
        const result = runBash(`
          source "$1"
          compose_timeout() { printf '{"services":{}}'; }
          run_control_plane_node() { cat >/dev/null; printf '%s' "$VALIDATOR_OUTPUT"; }
          set +e
          validate_compose "sha256:${'7'.repeat(64)}" mode
          rc=$?
          set -e
          printf '%s|%s' "$rc" "\${mode:-unset}"
        `, { VALIDATOR_OUTPUT: output }, script);
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /^[1-9][0-9]*\|unset$/);
      }
    }
  });

  it('escalates private render deletion errors and verifies final absence', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      for (const scenario of ['rm-error', 'reported-success-with-leak']) {
        const result = runBash(`
          source "$1"
          compose_timeout() { printf '{"services":{}}'; }
          run_control_plane_node() { cat >/dev/null; printf disabled; }
          rm() { [[ "$SCENARIO" == reported-success-with-leak ]]; }
          set +e
          validate_compose "sha256:${'8'.repeat(64)}" mode
          rc=$?
          set -e
          printf '%s|%s' "$rc" "$COMPOSE_RENDER_FILE"
        `, { SCENARIO: scenario }, script);
        assert.equal(result.status, 0, result.stderr);
        const [rc, renderFile] = result.stdout.split('|');
        assert.equal(rc, '125');
        assert.equal(existsSync(renderFile), true);
        assert.match(result.stderr, /private Compose render still exists/);
        if (scenario === 'rm-error') assert.match(result.stderr, /could not delete private Compose render/);
        rmSync(renderFile, { force: true });
      }
    }
  });

  it('snapshots the private environment once and ignores later live-file mutation', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-env-snapshot-`));
      const source = path.join(temp, '.env');
      const composeSource = path.join(temp, 'docker-compose.yml');
      writeFileSync(source, 'SNAPSHOT_VALUE=before\n', { mode: 0o600 });
      writeFileSync(composeSource, 'services: {}\n', { mode: 0o600 });
      try {
        const result = runBash(`
          source "$1"
          ENV_FILE="$ENV_SOURCE"
          ACTIVE_COMPOSE_FILE=/tmp/compose.yml
          COMPOSE_FILE="$COMPOSE_SOURCE"
          stat() {
            case "$2" in
              '%a') printf 600 ;;
              '%u') id -u ;;
              '%h') printf 1 ;;
              '%d:%i:%s:%Y:%Z') printf stable-source-identity ;;
              *) return 91 ;;
            esac
          }
          timeout() {
            while (( $# )); do
              if [[ "$1" == --env-file ]]; then cat "$2"; return 0; fi
              shift
            done
            return 92
          }
          snapshot_env_file
          if declare -F snapshot_compose_file >/dev/null; then snapshot_compose_file; fi
          snapshot=$ENV_SNAPSHOT
          mode=$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$snapshot")
          printf 'SNAPSHOT_VALUE=after\\n' > "$ENV_FILE"
          rendered=$(compose_timeout 30 config)
          if declare -F cleanup_env_snapshot_checked >/dev/null; then
            cleanup_compose_snapshot_checked
            cleanup_env_snapshot_checked
          else
            cleanup_compose_snapshots
          fi
          printf '%s|%s|%s' "$rendered" "$mode" "$snapshot"
        `, { COMPOSE_SOURCE: composeSource, ENV_SOURCE: source }, script);
        assert.equal(result.status, 0, result.stderr);
        const [rendered, mode, snapshot] = result.stdout.split('|');
        assert.equal(rendered, 'SNAPSHOT_VALUE=before');
        assert.equal(mode, '600');
        assert.equal(readFileSync(source, 'utf8'), 'SNAPSHOT_VALUE=after\n');
        assert.equal(existsSync(snapshot), false, `${name} must remove its environment snapshot`);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('rejects symlinked and permissive environment sources before snapshotting', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-unsafe-env-`));
      const source = path.join(temp, 'source.env');
      const linked = path.join(temp, 'linked.env');
      writeFileSync(source, 'VALUE=safe\n', { mode: 0o600 });
      try {
        const linkedResult = runBash(`
          source "$1"
          ENV_FILE="$LINKED"
          validate_env_source
        `, { LINKED: linked }, script);
        // Create only after the first missing-file check so this also verifies symlink refusal.
        spawnSync('ln', ['-s', source, linked]);
        const symlinkResult = runBash(`
          source "$1"
          ENV_FILE="$LINKED"
          validate_env_source
        `, { LINKED: linked }, script);
        assert.notEqual(linkedResult.status, 0);
        assert.notEqual(symlinkResult.status, 0);
        assert.match(symlinkResult.stderr, /regular non-symlink file/);

        const permissive = runBash(`
          source "$1"
          ENV_FILE="$SOURCE"
          stat() {
            case "$2" in
              '%a') printf 644 ;;
              '%u') id -u ;;
              '%h') printf 1 ;;
              *) return 91 ;;
            esac
          }
          validate_env_source
        `, { SOURCE: source }, script);
        assert.notEqual(permissive.status, 0);
        assert.match(permissive.stderr, /mode 400 or 600/);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('removes exact named ops containers after client timeout and exposes cleanup leaks', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const shell = `
        source "$1"
        leaked_name=''
        observed_run=''
        compose_timeout() {
          observed_run="$*"
          args=("$@")
          for ((i=0; i<\${#args[@]}; i++)); do
            [[ "\${args[$i]}" != --name ]] || leaked_name="\${args[$((i+1))]}"
          done
          return 124
        }
        timeout() {
          if [[ "$*" == *'docker container ls -a'*'--format'* ]]; then
            [[ -z "$leaked_name" ]] || printf '%s\\n' "$leaked_name"
            return 0
          fi
          if [[ "$*" == *'docker rm -f --'* ]]; then
            if [[ "$CLEANUP_FAIL" == 1 ]]; then return 55; fi
            leaked_name=''
            return 0
          fi
          return 93
        }
        set +e
        compose_ops_run 7 timeout-regression backup
        rc=$?
        set -e
        printf '%s|%s|%s' "$rc" "\${leaked_name:-absent}" "$observed_run"
      `;
      const cleaned = runBash(shell, { CLEANUP_FAIL: '0' }, script);
      assert.equal(cleaned.status, 0, cleaned.stderr);
      const [runRc, leaked, invocation] = cleaned.stdout.split('|');
      assert.equal(runRc, '124');
      assert.equal(leaked, 'absent');
      assert.match(invocation, new RegExp(`^7 --profile ops run --name astranull-${name}-timeout-regression-[0-9]+ --no-deps backup$`));

      const failedCleanup = runBash(shell, { CLEANUP_FAIL: '1' }, script);
      assert.equal(failedCleanup.status, 0, failedCleanup.stderr);
      const [cleanupRc, survivor] = failedCleanup.stdout.split('|');
      assert.equal(cleanupRc, '125');
      assert.match(survivor, new RegExp(`^astranull-${name}-timeout-regression-[0-9]+$`));
      assert.match(failedCleanup.stderr, /cleanup docker rm -f failed/);
      assert.match(failedCleanup.stderr, /still exists/);
      assert.match(failedCleanup.stderr, /Compose ops cleanup failed/);
    }
  });

  it('parent traps remove only this operation containers after real mid-run signals', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      for (const operation of ['ops', 'validator']) {
        for (const cleanupFail of operation === 'validator' ? ['0', '1'] : ['0']) {
          const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-${operation}-signal-`));
          const stateDir = path.join(temp, 'containers');
          const marker = path.join(temp, 'active');
          const fakeDocker = path.join(temp, 'docker');
          const unrelated = `astranull-${name}-unrelated-999999`;
          mkdirSync(stateDir);
          writeFakeTimeout(temp);
          writeFileSync(path.join(stateDir, unrelated), `${unrelated}\n`);
          writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
state_dir="$SIGNAL_STATE_DIR"
if [[ "$1 $2" == 'container ls' ]]; then
  for state in "$state_dir"/*; do [[ ! -f "$state" ]] || cat "$state" 2>/dev/null || true; done
  exit 0
fi
if [[ "$1 $2" == 'rm -f' ]]; then
  name="\${4}"
  [[ "$3" == -- && -n "$name" ]] || exit 91
  if [[ "$SIGNAL_CLEANUP_FAIL" == 1 ]]; then exit 55; fi
  rm -f -- "$state_dir/$name"
  exit 0
fi
if [[ "$1" == run ]]; then
  name=''
  args=("$@")
  for ((i=0; i<\${#args[@]}; i++)); do
    [[ "\${args[$i]}" != --name ]] || name="\${args[$((i+1))]}"
  done
  [[ -n "$name" ]] || exit 92
  printf '%s\n' "$name" > "$state_dir/$name"
  : > "$SIGNAL_MARKER"
  while :; do sleep 1; done
fi
exit 93
`);
          chmodSync(fakeDocker, 0o755);
          try {
            const result = runBash(`
              source "$1"
              previous=${'a'.repeat(40)}
              previous_compose=/tmp/astranull-signal.previous.yml
              target_compose=/tmp/astranull-signal.target.yml
              plain_host=''
              backup=''
              activated=0
              migration_started=0
              finished=0
              git() { :; }
              rebind_control_plane_image_tag() { :; }
              rebind_core_worker_image_tag() { :; }
              cleanup_backup_orphans() { :; }
              cleanup_compose_snapshots() { cleanup_compose_render_checked; }
              if [[ "$SCRIPT_KIND" == deploy ]]; then
                install_failure_traps
              else
                succeeded=0
                outage_started=0
                trap cleanup EXIT
                trap 'exit 130' HUP INT TERM
              fi
              compose_timeout() {
                if [[ "$*" == '30 --profile ops config --format json' ]]; then
                  printf '{"services":{}}'
                  return
                fi
                args=("$@")
                run_name=''
                for ((i=0; i<\${#args[@]}; i++)); do
                  [[ "\${args[$i]}" != --name ]] || run_name="\${args[$((i+1))]}"
                done
                timeout -k 5 30 docker run --name "$run_name" signal-fixture
              }
              (while [[ ! -e "$SIGNAL_MARKER" ]]; do sleep 0.01; done; kill -TERM -- -$$) &
              if [[ "$OPERATION" == ops ]]; then
                compose_ops_run 30 signal-mid-run backup
              else
                validate_compose "sha256:${'4'.repeat(64)}" mode
              fi
            `, {
              OPERATION: operation,
              PATH: `${temp}:${process.env.PATH}`,
              SCRIPT_KIND: name,
              SIGNAL_CLEANUP_FAIL: cleanupFail,
              SIGNAL_MARKER: marker,
              SIGNAL_STATE_DIR: stateDir,
            }, script);
            const operationStates = readdirSync(stateDir).filter((entry) => entry !== unrelated);
            if (cleanupFail === '0') {
              assert.ok([130, 143].includes(result.status), result.stderr);
              assert.deepEqual(operationStates, []);
            } else {
              assert.equal(result.status, 125, result.stderr);
              assert.ok(operationStates.some((entry) => entry.includes('release-node')));
              assert.match(result.stderr, /parent cleanup could not remove and verify every exact operation container/);
              assert.match(result.stderr, /operation container still exists after parent cleanup/);
            }
            assert.equal(existsSync(path.join(stateDir, unrelated)), true);
          } finally {
            rmSync(temp, { recursive: true, force: true });
          }
        }
      }
    }
  });

  it('ignores repeated cleanup signals and holds fd 9 through deploy rollback and restore fail-close', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-repeated-signals-`));
      const lockFile = path.join(temp, 'deploy.lock');
      const steps = path.join(temp, 'steps');
      const early = path.join(temp, 'lock-released-early');
      try {
        const result = runBash(`
          source "$1"
          exec 9>"$LOCK_FILE"
          python3 - <<'PY'
import fcntl
fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
PY
          critical_step() {
            printf '%s\n' "$1" >> "$STEPS"
            if ! python3 - "$LOCK_FILE" <<'PY'
import fcntl, sys
handle = open(sys.argv[1], 'a+')
try:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(0)
raise SystemExit(1)
PY
            then : > "$EARLY"; fi
            sleep 0.08
          }
          cleanup_active_operation_containers_checked() { critical_step containers; }
          cleanup_compose_render_checked() { critical_step render; }
          delete_plaintext_checked() { critical_step plaintext; }
          verify_release_state_journal_safe() { critical_step state; }
          cleanup_backup_orphans() { critical_step backups; }
          fail_closed_runtime() { critical_step fail-close; }
          stop_remove_services() { critical_step fail-close; }
          cleanup_compose_snapshots() { critical_step snapshots; }
          cleanup_compose_snapshot_checked() { critical_step compose-snapshot; }
          cleanup_env_snapshot_checked() { critical_step env-snapshot; }
          if [[ "$SCRIPT_KIND" == deploy ]]; then
            MODE=deploy
            previous=${'1'.repeat(40)}
            SHA=${'2'.repeat(40)}
            previous_compose=/tmp/repeated.previous.yml
            target_compose=/tmp/repeated.target.yml
            plain_host=/tmp/repeated-plaintext
            backup=/tmp/repeated.dump.enc
            activated=1
            had_current_release=0
            migration_started=0
            finished=0
            install_failure_traps
          else
            succeeded=0
            outage_started=1
            plain_host=/tmp/repeated-plaintext
            trap cleanup EXIT
            trap 'exit 130' HUP INT TERM
          fi
          (
            sleep 0.03
            kill -TERM $$
            sleep 0.03
            kill -HUP $$
            sleep 0.03
            kill -INT $$
            sleep 0.03
            kill -TERM $$
          ) &
          while :; do sleep 1; done
        `, {
          EARLY: early,
          LOCK_FILE: lockFile,
          SCRIPT_KIND: name,
          STEPS: steps,
        }, script);
        assert.equal(result.status, 130, result.stderr);
        assert.equal(existsSync(early), false, `${name} released fd 9 before cleanup completed`);
        const observed = readFileSync(steps, 'utf8');
        for (const expected of ['containers', 'render', 'plaintext', 'fail-close', 'state']) {
          assert.match(observed, new RegExp(`^|\\n${expected}\\n?`), `${name} missed ${expected}`);
        }
        if (name === 'deploy') {
          assert.match(observed, /backups/);
          assert.match(observed, /snapshots/);
        } else {
          assert.match(observed, /compose-snapshot/);
          assert.match(observed, /env-snapshot/);
        }
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('keeps successful deploy final cleanup signal-immune and locked until every check completes', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-success-cleanup-signals-'));
    const lockFile = path.join(temp, 'deploy.lock');
    const steps = path.join(temp, 'steps');
    const started = path.join(temp, 'started');
    const early = path.join(temp, 'lock-released-early');
    try {
      const result = runBash(`
        source "$1"
        exec 9>"$LOCK_FILE"
        python3 - <<'PY'
import fcntl
fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
PY
        critical_step() {
          printf '%s\n' "$1" >> "$STEPS"
          : > "$STARTED"
          if ! python3 - "$LOCK_FILE" <<'PY'
import fcntl, sys
handle = open(sys.argv[1], 'a+')
try:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(0)
raise SystemExit(1)
PY
          then : > "$EARLY"; fi
          sleep 0.08
        }
        cleanup_active_operation_containers_checked() { critical_step containers; }
        delete_plaintext_checked() { critical_step plaintext; }
        cleanup_backup_orphans() { critical_step backups; }
        verify_release_state_settled() { critical_step state; }
        cleanup_compose_snapshots() { critical_step snapshots; }
        bounded_prune_release_images() { critical_step images; }
        plain_host=/tmp/success-plaintext
        (
          while [[ ! -e "$STARTED" ]]; do sleep 0.01; done
          kill -TERM $$
          kill -HUP $$
          kill -INT $$
          kill -TERM $$
        ) &
        finalize_success_cleanup
        printf complete
      `, { EARLY: early, LOCK_FILE: lockFile, STARTED: started, STEPS: steps });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'complete');
      assert.equal(existsSync(early), false);
      assert.deepEqual(readFileSync(steps, 'utf8').trim().split('\n'), [
        'containers', 'plaintext', 'backups', 'state', 'snapshots', 'images',
      ]);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('kills a detached restore-db process on signal before releasing the shared lock', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-db-real-signal-'));
    const fakeDocker = path.join(temp, 'docker');
    const stateName = path.join(temp, 'container-name');
    const childPidFile = path.join(temp, 'child.pid');
    const started = path.join(temp, 'started');
    const cleaned = path.join(temp, 'cleaned');
    const lockReleasedEarly = path.join(temp, 'lock-released-early');
    const lockHeldMarker = path.join(temp, 'lock-held');
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'container ls' ]]; then
  [[ ! -f "$STATE_NAME" ]] || cat "$STATE_NAME"
  exit 0
fi
if [[ "$1 $2" == 'rm -f' ]]; then
  name="\${4}"
  [[ "$3" == -- && -f "$STATE_NAME" && "$name" == "$(cat "$STATE_NAME")" ]] || exit 91
  if [[ ! -e "$LOCK_HELD_MARKER" ]]; then
    : > "$LOCK_RELEASED_EARLY"
    exit 92
  fi
  pid=$(cat "$CHILD_PID_FILE")
  kill -TERM "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$STATE_NAME"
  : > "$CLEANED_MARKER"
  exit 0
fi
if [[ "$1" == run && "$2" == --name && -n "$3" ]]; then
  printf '%s\\n' "$3" > "$STATE_NAME"
  exec python3 - "$CHILD_PID_FILE" "$STARTED_MARKER" <<'PY'
import pathlib
import subprocess
import sys

child = subprocess.Popen(['sleep', '60'], start_new_session=True)
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
pathlib.Path(sys.argv[2]).touch()
child.wait()
PY
fi
exit 93
`);
    chmodSync(fakeDocker, 0o755);
    try {
      const result = runBash(`
        source "$1"
        : > "$LOCK_HELD_MARKER"
        succeeded=0
        outage_started=1
        plain_host=''
        cleanup_compose_render_checked() { :; }
        cleanup_compose_snapshot_checked() { :; }
        cleanup_env_snapshot_checked() { :; }
        stop_remove_services() { :; }
        compose_timeout() {
          args=("$@")
          name=''
          for ((i=0; i<\${#args[@]}; i++)); do
            [[ "\${args[$i]}" != --name ]] || name="\${args[$((i+1))]}"
          done
          [[ -n "$name" ]] || return 94
          docker run --name "$name"
        }
        trap cleanup EXIT
        trap 'exit 130' HUP INT TERM
        (while [[ ! -e "$STARTED_MARKER" ]]; do sleep 0.01; done; kill -TERM -- -$$) &
        compose_ops_run 600 restore-db-archive -T restore-db sh -c destructive
      `, {
        CHILD_PID_FILE: childPidFile,
        CLEANED_MARKER: cleaned,
        LOCK_HELD_MARKER: lockHeldMarker,
        LOCK_RELEASED_EARLY: lockReleasedEarly,
        PATH: `${temp}:${process.env.PATH}`,
        STARTED_MARKER: started,
        STATE_NAME: stateName,
      }, RESTORE);
      assert.notEqual(result.status, 0, result.stderr);
      assert.equal(existsSync(cleaned), true, 'parent cleanup must remove the named one-shot');
      assert.equal(existsSync(stateName), false);
      assert.equal(existsSync(lockReleasedEarly), false, 'cleanup must run before lock release');
      const childPid = Number(readFileSync(childPidFile, 'utf8'));
      let alive = true;
      try { process.kill(childPid, 0); } catch { alive = false; }
      assert.equal(alive, false, `destructive child ${childPid} survived restore cleanup`);
    } finally {
      if (existsSync(childPidFile)) {
        const childPid = Number(readFileSync(childPidFile, 'utf8'));
        try { process.kill(childPid, 'SIGKILL'); } catch {}
      }
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('fails visibly when plaintext deletion fails or reports success without absence', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      for (const scenario of ['rm-error', 'still-present']) {
        const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-plaintext-${scenario}-`));
        const plaintext = path.join(temp, 'sensitive.dump');
        writeFileSync(plaintext, 'secret');
        try {
          const result = runBash(`
            source "$1"
            rm() { [[ "$SCENARIO" == still-present ]]; }
            set +e
            delete_plaintext_checked "$PLAINTEXT"
            rc=$?
            set -e
            printf '%s|%s' "$rc" "$([[ -e "$PLAINTEXT" || -L "$PLAINTEXT" ]] && printf present || printf absent)"
          `, { PLAINTEXT: plaintext, SCENARIO: scenario }, script);
          assert.equal(result.status, 0, result.stderr);
          assert.equal(result.stdout, '1|present');
          if (scenario === 'rm-error') assert.match(result.stderr, /WARNING: plaintext deletion command failed/);
          assert.match(result.stderr, /CRITICAL: plaintext backup still exists/);
        } finally {
          rmSync(temp, { recursive: true, force: true });
        }
      }
    }
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
      cleanup_active_operation_containers_checked() { return 0; }
      cleanup_backup_orphans() { return 0; }
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

  it('uses bounded stop, kill fallback, rm, and per-service absence verification in both scripts', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-stop-remove-`));
      const callLog = path.join(temp, 'calls.log');
      try {
        const shell = `
          source "$1"
          compose_timeout() {
            printf '%s\\n' "$*" >> "$CALL_LOG"
            case "$*" in
              '120 stop alpha beta') return 41 ;;
              '120 kill alpha beta') [[ "$SCENARIO" == recovered ]] ;;
              '120 rm -f alpha beta') [[ "$SCENARIO" == recovered ]] ;;
              '30 ps --all -q alpha') return 0 ;;
              '30 ps --all -q beta') [[ "$SCENARIO" == recovered ]] || printf surviving-beta ;;
              *) return 97 ;;
            esac
          }
          stop_remove_services alpha beta
        `;
        const recovered = runBash(shell, { CALL_LOG: callLog, SCENARIO: 'recovered' }, script);
        assert.equal(recovered.status, 0, recovered.stderr);
        assert.match(recovered.stderr, /attempting kill fallback/);
        assert.deepEqual(readFileSync(callLog, 'utf8').trim().split('\n'), [
          '120 stop alpha beta',
          '120 kill alpha beta',
          '120 rm -f alpha beta',
          '30 ps --all -q alpha',
          '30 ps --all -q beta',
        ]);

        writeFileSync(callLog, '');
        const survivor = runBash(shell, { CALL_LOG: callLog, SCENARIO: 'survivor' }, script);
        assert.notEqual(survivor.status, 0);
        assert.match(survivor.stderr, /beta still has container\(s\): surviving-beta/);
        const survivorCalls = readFileSync(callLog, 'utf8');
        assert.match(survivorCalls, /120 stop alpha beta[\s\S]*120 kill alpha beta[\s\S]*120 rm -f alpha beta/);
        assert.match(survivorCalls, /30 ps --all -q alpha[\s\S]*30 ps --all -q beta/);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('replaces every old runtime service before core Compose up in both scripts', () => {
    const expectedServices = 'caddy control-plane probe-worker password-recovery-worker test-policy-runner connector-poll-scheduler connector-poll-runner';
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-replace-runtime-`));
      const calls = path.join(temp, 'calls.log');
      try {
        const result = runBash(`
          source "$1"
          stop_remove_services() { printf 'replace|%s\\n' "$*" >> "$CALLS"; }
          compose_timeout() { printf 'compose|%s\\n' "$*" >> "$CALLS"; }
          start_core_stack
        `, { CALLS: calls }, script);
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(readFileSync(calls, 'utf8').trim().split('\n'), [
          `replace|${expectedServices}`,
          'compose|300 up -d --wait --wait-timeout 240 postgres control-plane probe-worker password-recovery-worker test-policy-runner caddy',
        ]);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('propagates bounded pg_restore structural rejection of a PGDMP-prefix fake', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-archive-list-`));
      const fakeArchive = path.join(temp, 'prefix-only.dump');
      const calls = path.join(temp, 'calls.log');
      writeFileSync(fakeArchive, 'PGDMP-not-a-real-custom-archive', { mode: 0o600 });
      try {
        const result = runBash(`
          source "$1"
          BACKUP_DIR="$ARCHIVE_DIR"
          stat() {
            case "$2" in
              '%a') printf 600 ;;
              '%u') id -u ;;
              '%h') printf 1 ;;
              *) return 91 ;;
            esac
          }
          compose_timeout() {
            printf '%s\\n' "$*" >> "$CALLS"
            [[ "$(head -c 5 "$FAKE_ARCHIVE")" == PGDMP ]] || return 96
            return 42
          }
          verify_named_container_absent() { :; }
          remove_named_container_checked() { :; }
          if declare -F restore_plaintext_identity >/dev/null; then
            expected_plaintext_sha256=${'a'.repeat(64)}
            restore_plaintext_identity() { printf stable; }
            restore_plaintext_sha256() { printf '%s' "$expected_plaintext_sha256"; }
          fi
          validate_plaintext_archive "$FAKE_ARCHIVE"
        `, { ARCHIVE_DIR: temp, CALLS: calls, FAKE_ARCHIVE: fakeArchive }, script);
        assert.equal(result.status, 42, result.stderr);
        const invocation = readFileSync(calls, 'utf8');
        assert.match(invocation, /^60 --profile ops run --name astranull-(?:deploy|restore)-pg-restore-list-[0-9]+ --no-deps /);
        assert.match(invocation, /backup-dump sh -eu -c exec pg_restore --list/);
        assert.match(invocation, /\/backup\/prefix-only\.dump/);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('revalidates the authenticated restore plaintext digest after extraction', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-plaintext-digest-'));
    const archive = path.join(temp, 'authenticated.dump');
    writeFileSync(archive, 'PGDMP-authenticated-content', { mode: 0o600 });
    const expected = createHash('sha256').update(readFileSync(archive)).digest('hex');
    try {
      const valid = runBash(`
        source "$1"
        BACKUP_DIR="$ARCHIVE_DIR"
        expected_plaintext_sha256="$EXPECTED"
        compose_ops_run() { :; }
        validate_plaintext_archive "$ARCHIVE"
      `, { ARCHIVE: archive, ARCHIVE_DIR: temp, EXPECTED: expected }, RESTORE);
      assert.equal(valid.status, 0, valid.stderr);

      writeFileSync(archive, 'PGDMP-tampered-content-now', { mode: 0o600 });
      const tampered = runBash(`
        source "$1"
        BACKUP_DIR="$ARCHIVE_DIR"
        expected_plaintext_sha256="$EXPECTED"
        compose_ops_run() { :; }
        validate_plaintext_archive "$ARCHIVE"
      `, { ARCHIVE: archive, ARCHIVE_DIR: temp, EXPECTED: expected }, RESTORE);
      assert.notEqual(tampered.status, 0);
      assert.match(tampered.stderr, /digest no longer matches/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
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
        ensure_postgres_ready_for_backup "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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
        ensure_postgres_ready_for_backup "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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
        ensure_postgres_ready_for_backup "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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
        ensure_postgres_ready_for_backup "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      `);
      assert.equal(unknownVolumeState.status, 1);
      assert.match(unknownVolumeState.stderr, /could not verify whether postgres data volume/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('keeps a persisted legacy observation compatible across a failed pre-activation retry', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-complete-fleet-bridge-'));
    const stateDir = path.join(temp, 'state');
    const controlState = path.join(stateDir, 'control-plane-image-tag');
    const coreState = path.join(stateDir, 'core-worker-image-state');
    const tag = '7'.repeat(40);
    const imageId = `sha256:${'8'.repeat(64)}`;
    const requested = '9'.repeat(40);
    const shell = `
      source "$1"
      SHA="$REQUESTED"
      DEPLOY_STATE_DIR="$STATE_DIR"
      CONTROL_PLANE_IMAGE_TAG_FILE="$CONTROL_STATE"
      CORE_WORKER_IMAGE_STATE_FILE="$CORE_STATE"
      CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
      RELEASE_VALIDATOR_IMAGE_STATE_FILE="$STATE_DIR/release-validator-image-state"
      CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
      PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
      compose_timeout() {
        [[ "$1" == 30 && "$2" == ps ]] || return 91
        service="\${!#}"
        if [[ "$service" == connector-poll-scheduler || "$service" == connector-poll-runner ]]; then return 0; fi
        if [[ "$SCENARIO" == partial && "$service" == test-policy-runner ]]; then return 0; fi
        printf '%s-cid' "$service"
      }
      timeout() {
        [[ "$1 $2 $3 $4 $5 $6" == '-k 5 30 docker inspect --format' ]] || return 92
        if [[ "$7" == '{{.Config.Image}}' ]]; then printf 'astranull-control-plane:%s\\n' "$TAG";
        elif [[ "$7" == '{{.Image}}' ]]; then printf '%s\\n' "$IMAGE_ID";
        else return 93; fi
      }
      rebind_control_plane_image_tag() { [[ "$1" == "$TAG" && "$2" == "$IMAGE_ID" ]]; }
      rebind_core_worker_image_tag() { [[ "$1" == "$TAG" && "$2" == "$IMAGE_ID" ]]; }
      check_postgres() { :; }
      check_control_plane() { :; }
      check_core_workers() { :; }
      check_connector_workers() { :; }
      verify_services_absent() { :; }
      prepare_previous_release_images "$REQUESTED"
      first="$previous_control_plane_tag|$previous_control_plane_image_id|$previous_core_worker_tag|$previous_core_worker_image_id"
      # Simulate a first candidate failing before activation: persisted state remains while
      # the legacy containers still have tag-based Config.Image values.
      prepare_previous_release_images "$REQUESTED"
      second="$previous_control_plane_tag|$previous_control_plane_image_id|$previous_core_worker_tag|$previous_core_worker_image_id"
      [[ "$first" == "$second" ]]
      prepare_canonical_current_release "$TAG" "$IMAGE_ID"
      release_bundle_load "$CURRENT_RELEASE_BUNDLE_FILE"
      [[ "$release_bundle_control_tag|$release_bundle_control_image_id|$release_bundle_core_tag|$release_bundle_core_image_id" == "$second" ]]
      [[ ! -e "$PENDING_RELEASE_BUNDLE_FILE" && ! -L "$PENDING_RELEASE_BUNDLE_FILE" ]]
      printf '%s|canonical' "$second"
    `;
    try {
      mkdirSync(stateDir, { recursive: true });
      writeFileSync(controlState, `${tag}\n`, { mode: 0o600 });
      const bridged = runBash(shell, {
        CONTROL_STATE: controlState,
        CORE_STATE: coreState,
        IMAGE_ID: imageId,
        REQUESTED: requested,
        SCENARIO: 'complete',
        STATE_DIR: stateDir,
        TAG: tag,
      });
      assert.equal(bridged.status, 0, bridged.stderr);
      assert.equal(bridged.stdout, `${tag}|${imageId}|${tag}|${imageId}|canonical`);
      assert.equal(readFileSync(controlState, 'utf8'), `${tag}\n${imageId}\n`);
      assert.equal(existsSync(path.join(stateDir, 'release-image-current')), true);
      assert.equal(existsSync(path.join(stateDir, 'release-image-pending')), false);

      rmSync(path.join(stateDir, 'release-image-current'), { force: true });
      rmSync(path.join(stateDir, 'release-validator-image-state'), { force: true });
      rmSync(coreState, { force: true });
      writeFileSync(controlState, `${tag}\n`, { mode: 0o600 });
      const partial = runBash(shell, {
        CONTROL_STATE: controlState,
        CORE_STATE: coreState,
        IMAGE_ID: imageId,
        REQUESTED: requested,
        SCENARIO: 'partial',
        STATE_DIR: stateDir,
        TAG: tag,
      });
      assert.notEqual(partial.status, 0);
      assert.match(partial.stderr, /all four services must be running/);
      assert.equal(existsSync(coreState), false);
      assert.equal(existsSync(path.join(stateDir, 'release-image-current')), false);
      assert.equal(readFileSync(controlState, 'utf8'), `${tag}\n`);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('initializes no-state first boot only from the requested archive identity on a genuinely fresh host', () => {
    const requested = 'a'.repeat(40);
    const previousHead = 'b'.repeat(40);
    const imageId = `sha256:${'c'.repeat(64)}`;
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-fresh-identity-'));
    const runScenario = (scenario) => {
      const stateDir = path.join(temp, scenario);
      const calls = path.join(stateDir, 'calls.log');
      mkdirSync(stateDir, { recursive: true });
      const result = runBash(`
        source "$1"
        SHA="$REQUESTED"
        previous="$PREVIOUS_HEAD"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
        compose_timeout() {
          case "$*" in
            '30 ps -q '*) return 0 ;;
            '30 ps --all -q postgres') [[ "$SCENARIO" != postgres ]] || printf postgres-cid ;;
            '30 ps --all -q control-plane') [[ "$SCENARIO" != stopped-runtime ]] || printf stopped-control ;;
            '30 ps --all -q '*) return 0 ;;
            *) return 91 ;;
          esac
        }
        build_control_plane_from_commit() {
          printf 'build|%s\\n' "$1" >> "$CALLS"
          built_control_plane_image_id="$IMAGE_ID"
        }
        postgres_volume_name() { printf aws_pgdata; }
        docker_volume_exists() { [[ "$SCENARIO" == volume ]]; }
        rebind_control_plane_image_tag() { :; }
        rebind_core_worker_image_tag() { :; }
        prepare_previous_release_images "$REQUESTED"
        printf '%s|%s|%s|%s|%s' "$fresh_bootstrap" "$previous_control_plane_tag" "$previous_control_plane_image_id" "$previous_core_worker_tag" "$previous_core_worker_image_id"
      `, {
        CALLS: calls,
        IMAGE_ID: imageId,
        PREVIOUS_HEAD: previousHead,
        REQUESTED: requested,
        SCENARIO: scenario,
        STATE_DIR: stateDir,
      });
      return { calls, result, stateDir };
    };

    try {
      const fresh = runScenario('fresh');
      assert.equal(fresh.result.status, 0, fresh.result.stderr);
      assert.equal(fresh.result.stdout, `1|${requested}|${imageId}|${requested}|${imageId}`);
      assert.equal(readFileSync(fresh.calls, 'utf8'), `build|${requested}\n`);
      assert.equal(existsSync(path.join(fresh.stateDir, 'control-plane-image-tag')), false);
      assert.equal(existsSync(path.join(fresh.stateDir, 'core-worker-image-state')), false);
      assert.doesNotMatch(fresh.result.stdout, new RegExp(previousHead));

      for (const [scenario, message] of [
        ['postgres', /Postgres container but no exact runtime state/],
        ['volume', /Postgres data volume aws_pgdata but no exact runtime state/],
        ['stopped-runtime', /only stopped container state/],
      ]) {
        const blocked = runScenario(scenario);
        assert.notEqual(blocked.result.status, 0, scenario);
        assert.match(blocked.result.stderr, message);
        assert.equal(existsSync(path.join(blocked.stateDir, 'control-plane-image-tag')), false);
        assert.equal(existsSync(path.join(blocked.stateDir, 'core-worker-image-state')), false);
      }
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('resumes first boot only from an exact pending journal and existing Postgres volume', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-first-boot-resume-'));
    const stateDir = path.join(temp, 'state');
    const tag = '7'.repeat(40);
    const imageId = `sha256:${'8'.repeat(64)}`;
    try {
      const resumed = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
        PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
        RELEASE_VALIDATOR_IMAGE_STATE_FILE="$STATE_DIR/release-validator-image-state"
        write_pending_release_bundle "$TAG" "$IMAGE_ID" "$TAG" "$IMAGE_ID" "$TAG" "$IMAGE_ID" 0 '' ''
        release_runtime_matches_bundle_file() { return 1; }
        release_runtime_services_absent() { return 0; }
        verify_services_absent() { return 0; }
        reconcile_pending_release_bundle
        assert_resumable_first_boot_pending "$TAG" "$IMAGE_ID"
        started=0
        compose_timeout() {
          case "$*" in
            '30 ps --all -q postgres') ((started)) && printf postgres-cid; return 0 ;;
            '180 up -d --no-deps --wait --wait-timeout 120 postgres') started=1; return 0 ;;
            *) return 91 ;;
          esac
        }
        postgres_volume_name() { printf aws_pgdata; }
        docker_volume_exists() { return 0; }
        check_postgres() { ((started)); }
        ensure_postgres_ready_for_backup "$IMAGE_ID"
        printf '%s|%s' "$release_state_preactivation_pending" "$started"
      `, { IMAGE_ID: imageId, STATE_DIR: stateDir, TAG: tag });
      assert.equal(resumed.status, 0, resumed.stderr);
      assert.equal(resumed.stdout, '1|1');

      const mismatch = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
        PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
        release_state_preactivation_pending=1
        assert_resumable_first_boot_pending "$TAG" "sha256:${'9'.repeat(64)}"
      `, { STATE_DIR: stateDir, TAG: tag });
      assert.notEqual(mismatch.status, 0);
      assert.match(mismatch.stderr, /does not match the exact requested release/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('uses target Compose while restoring exact durable core/ops identity on automatic rollback', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-hybrid-rollback-'));
    const legacyCompose = path.join(temp, 'legacy.yml');
    const targetCompose = path.join(temp, 'target.yml');
    const callLog = path.join(temp, 'calls.log');
    const oldTag = 'b'.repeat(40);
    const coreTag = 'a'.repeat(40);
    const targetTag = 'c'.repeat(40);
    const oldImageId = `sha256:${'2'.repeat(64)}`;
    const coreImageId = `sha256:${'3'.repeat(64)}`;
    writeFileSync(legacyCompose, 'services:\n  control-plane:\n    build:\n      context: ../..\n  caddy:\n    image: caddy\n');
    writeFileSync(targetCompose, 'services:\n  control-plane:\n    image: astranull-control-plane:${ASTRANULL_CONTROL_PLANE_IMAGE_TAG}\n  probe-worker: {}\n  password-recovery-worker: {}\n  test-policy-runner: {}\n');

    try {
      const result = runBash(`
        source "$1"
        MODE=deploy
        previous="$OLD_TAG"
        SHA="$TARGET_TAG"
        previous_control_plane_tag="$OLD_TAG"
        previous_control_plane_image_id="$OLD_IMAGE_ID"
        previous_core_worker_tag="$CORE_TAG"
        previous_core_worker_image_id="$CORE_IMAGE_ID"
        previous_compose="$LEGACY_COMPOSE"
        target_compose="$TARGET_COMPOSE"
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        had_current_release=1
        previous_release_validator_tag="${'8'.repeat(40)}"
        previous_release_validator_image_id="sha256:${'9'.repeat(64)}"
        migration_started=1
        cleanup_active_operation_containers_checked() { :; }
        cleanup_backup_orphans() { :; }
        write_pending_release_bundle() { printf 'journal|%s\n' "$*" >> "\${CALL_LOG:-/dev/null}"; }
        promote_pending_release_bundle() { printf 'promote\n' >> "\${CALL_LOG:-/dev/null}"; }
        cleanup_compose_snapshots() { :; }
        git() { printf 'git|%s\\n' "$*" >> "$CALL_LOG"; }
        rebind_control_plane_image_tag() { printf 'rebind-control|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        rebind_core_worker_image_tag() { printf 'rebind-core|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        start_core_stack() { printf 'start-core|%s|%s|%s|%s\\n' "$ACTIVE_COMPOSE_FILE" "$ASTRANULL_CONTROL_PLANE_IMAGE_TAG" "$ASTRANULL_WORKER_IMAGE_TAG" "$ASTRANULL_IMAGE_TAG" >> "$CALL_LOG"; }
        check_control_plane() { :; }
        check_core_workers() { :; }
        verify_control_plane_image_tag() { :; }
        verify_workers_image_tag() { printf 'verify-core|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        persist_control_plane_image_state() { :; }
        persist_core_worker_image_state() { printf 'persist-core|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        clear_connector_image_state() { printf 'clear-connectors\\n' >> "$CALL_LOG"; }
        rollback_on_error 73
      `, {
        CALL_LOG: callLog,
        CORE_IMAGE_ID: coreImageId,
        CORE_TAG: coreTag,
        LEGACY_COMPOSE: legacyCompose,
        OLD_IMAGE_ID: oldImageId,
        OLD_TAG: oldTag,
        TARGET_COMPOSE: targetCompose,
        TARGET_TAG: targetTag,
      });
      assert.equal(result.status, 73, result.stderr);
      assert.match(result.stderr, new RegExp(`core/ops workers ${coreTag}@${coreImageId} with orchestration checkout ${targetTag}; connector_enabled=0`));
      const calls = readFileSync(callLog, 'utf8');
      assert.match(calls, new RegExp(`git\\|checkout -q --detach ${targetTag}`));
      assert.match(calls, new RegExp(`rebind-control\\|${oldTag}\\|${oldImageId}`));
      assert.match(calls, new RegExp(`rebind-core\\|${coreTag}\\|${coreImageId}`));
      assert.match(calls, new RegExp(`start-core\\|${targetCompose.replaceAll('/', '\\/')}\\|${oldTag}\\|${coreTag}\\|${coreTag}`));
      assert.match(calls, new RegExp(`verify-core\\|${coreTag}\\|${coreImageId}`));
      assert.match(calls, new RegExp(`journal\\|${oldTag} ${oldImageId} ${coreTag} ${coreImageId}`));
      assert.match(calls, /promote/);
      assert.ok(calls.indexOf('rebind-core|') < calls.indexOf('start-core|'));
      assert.doesNotMatch(calls, new RegExp(`start-core\\|${legacyCompose.replaceAll('/', '\\/')}\\|`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });


  it('restores a compatible persisted connector image after core rollback health', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-connector-rollback-'));
    const callLog = path.join(temp, 'calls.log');
    const oldTag = 'd'.repeat(40);
    const targetTag = 'e'.repeat(40);
    const connectorTag = 'f'.repeat(40);
    const coreTag = 'c'.repeat(40);
    const controlImageId = `sha256:${'3'.repeat(64)}`;
    const connectorImageId = `sha256:${'4'.repeat(64)}`;
    const coreImageId = `sha256:${'5'.repeat(64)}`;
    try {
      const result = runBash(`
        source "$1"
        MODE=deploy
        previous="$OLD_TAG"
        SHA="$TARGET_TAG"
        previous_control_plane_tag="$OLD_TAG"
        previous_control_plane_image_id="$CONTROL_IMAGE_ID"
        previous_core_worker_tag="$CORE_TAG"
        previous_core_worker_image_id="$CORE_IMAGE_ID"
        previous_connector_enabled=1
        validated_connector_mode=enabled
        previous_connector_tag="$CONNECTOR_TAG"
        previous_connector_image_id="$CONNECTOR_IMAGE_ID"
        previous_compose="$DUMMY_COMPOSE"
        target_compose="$DUMMY_COMPOSE"
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        had_current_release=1
        previous_release_validator_tag="${'8'.repeat(40)}"
        previous_release_validator_image_id="sha256:${'9'.repeat(64)}"
        migration_started=1
        cleanup_active_operation_containers_checked() { :; }
        cleanup_backup_orphans() { :; }
        write_pending_release_bundle() { printf 'journal|%s\n' "$*" >> "\${CALL_LOG:-/dev/null}"; }
        promote_pending_release_bundle() { printf 'promote\n' >> "\${CALL_LOG:-/dev/null}"; }
        cleanup_compose_snapshots() { :; }
        git() { :; }
        rebind_control_plane_image_tag() { printf 'rebind-control|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        rebind_core_worker_image_tag() { printf 'rebind-core|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        rebind_connector_image_tag() { printf 'rebind-connector|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        connector_image_supports_split_mode() { printf 'compat|%s\\n' "$1" >> "$CALL_LOG"; [[ "$1" == "$CONNECTOR_IMAGE_ID" ]]; }
        start_core_stack() { printf 'start-core\\n' >> "$CALL_LOG"; }
        check_control_plane() { printf 'health-control\\n' >> "$CALL_LOG"; }
        check_core_workers() { printf 'health-core\\n' >> "$CALL_LOG"; }
        verify_control_plane_image_tag() { :; }
        verify_workers_image_tag() { :; }
        start_connector_workers() { printf 'start-connectors|%s\\n' "$ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG" >> "$CALL_LOG"; }
        check_connector_workers() { printf 'health-connectors\\n' >> "$CALL_LOG"; }
        verify_connector_workers_image_tag() { printf 'verify-connectors|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        persist_control_plane_image_state() { :; }
        persist_core_worker_image_state() { printf 'persist-core|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        persist_connector_image_state() { printf 'persist-connectors|%s|%s\\n' "$1" "$2" >> "$CALL_LOG"; }
        clear_connector_image_state() { exit 95; }
        rollback_on_error 73
      `, {
        CALL_LOG: callLog,
        CONNECTOR_IMAGE_ID: connectorImageId,
        CONNECTOR_TAG: connectorTag,
        CONTROL_IMAGE_ID: controlImageId,
        CORE_IMAGE_ID: coreImageId,
        CORE_TAG: coreTag,
        DUMMY_COMPOSE: path.join(temp, 'compose.yml'),
        OLD_TAG: oldTag,
        TARGET_TAG: targetTag,
      });
      assert.equal(result.status, 73, result.stderr);
      assert.match(result.stderr, /connector_enabled=1/);
      const calls = readFileSync(callLog, 'utf8');
      assert.match(calls, new RegExp(`rebind-core\\|${coreTag}\\|${coreImageId}`));
      assert.match(calls, new RegExp(`journal\\|${oldTag} ${controlImageId} ${coreTag} ${coreImageId}`));
      assert.match(calls, /promote/);
      assert.match(calls, new RegExp(`rebind-connector\\|${connectorTag}\\|${connectorImageId}`));
      assert.match(calls, new RegExp(`verify-connectors\\|${connectorTag}\\|${connectorImageId}`));
      assert.match(calls, new RegExp(`journal\\|[^\\n]* 1 ${connectorTag} ${connectorImageId}`));
      assert.ok(calls.indexOf('health-core') < calls.indexOf('start-connectors'));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
  it('never starts stale prior connectors when the validated release mode is disabled', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-disabled-connector-rollback-'));
    const calls = path.join(temp, 'calls.log');
    const tag = 'a'.repeat(40);
    const controlId = `sha256:${'1'.repeat(64)}`;
    const coreId = `sha256:${'2'.repeat(64)}`;
    const connectorId = `sha256:${'3'.repeat(64)}`;
    try {
      const result = runBash(`
        source "$1"
        MODE=deploy
        previous="$TAG"
        SHA="$TAG"
        previous_control_plane_tag="$TAG"
        previous_control_plane_image_id="$CONTROL_ID"
        previous_core_worker_tag="$TAG"
        previous_core_worker_image_id="$CORE_ID"
        previous_connector_enabled=1
        previous_connector_tag="$TAG"
        previous_connector_image_id="$CONNECTOR_ID"
        validated_connector_mode=disabled
        previous_compose=/tmp/previous.yml
        target_compose=/tmp/target.yml
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        had_current_release=1
        previous_release_validator_tag="${'8'.repeat(40)}"
        previous_release_validator_image_id="sha256:${'9'.repeat(64)}"
        cleanup_active_operation_containers_checked() { :; }
        cleanup_backup_orphans() { :; }
        write_pending_release_bundle() { printf 'journal|%s\n' "$*" >> "\${CALL_LOG:-/dev/null}"; }
        promote_pending_release_bundle() { printf 'promote\n' >> "\${CALL_LOG:-/dev/null}"; }
        cleanup_compose_snapshots() { :; }
        git() { :; }
        rebind_control_plane_image_tag() { printf 'control\\n' >> "$CALLS"; }
        rebind_core_worker_image_tag() { printf 'core\\n' >> "$CALLS"; }
        rebind_connector_image_tag() { printf 'UNSAFE-rebind-connector\\n' >> "$CALLS"; return 91; }
        connector_image_supports_split_mode() { printf 'UNSAFE-compat\\n' >> "$CALLS"; return 92; }
        start_core_stack() { printf 'start-core|%s|%s|%s\\n' "$ASTRANULL_CONTROL_PLANE_IMAGE_ID" "$ASTRANULL_CORE_WORKER_IMAGE_ID" "$ASTRANULL_CONNECTOR_WORKER_IMAGE_ID" >> "$CALLS"; }
        check_control_plane() { :; }
        check_core_workers() { :; }
        verify_control_plane_image_tag() { :; }
        verify_workers_image_tag() { :; }
        start_connector_workers() { printf 'UNSAFE-start-connectors\\n' >> "$CALLS"; return 93; }
        persist_control_plane_image_state() { :; }
        persist_core_worker_image_state() { :; }
        persist_connector_image_state() { printf 'UNSAFE-persist-connectors\\n' >> "$CALLS"; return 94; }
        clear_connector_image_state() { printf 'clear-connectors\\n' >> "$CALLS"; }
        rollback_on_error 73
      `, {
        CALLS: calls,
        CALL_LOG: calls,
        CONNECTOR_ID: connectorId,
        CONTROL_ID: controlId,
        CORE_ID: coreId,
        TAG: tag,
      });
      assert.equal(result.status, 73, result.stderr);
      assert.match(result.stderr, /prior connector state ignored because validated release connector mode is disabled/);
      assert.match(result.stderr, /connector_enabled=0/);
      const log = readFileSync(calls, 'utf8');
      assert.match(log, new RegExp(`start-core\\|${controlId}\\|${coreId}\\|${coreId}`));
      assert.match(log, /journal\|[^\n]* 0  $/m);
      assert.match(log, /promote/);
      assert.doesNotMatch(log, /UNSAFE/);
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
  args=("$@")
  iid_file=''
  for ((i=0; i<\${#args[@]}; i++)); do
    [[ "\${args[$i]}" != --iidfile ]] || iid_file="\${args[$((i+1))]}"
  done
  [[ -n "$iid_file" ]]
  cat >/dev/null
  printf '%s\n' "$REBUILT_IMAGE_ID" > "$iid_file"
  printf '%s\n' "$REBUILT_IMAGE_ID" > "$TAG_FILE"
elif [[ "$1 $2" == 'image inspect' ]]; then
  if [[ "$5" == "$OLD_IMAGE_ID" ]]; then printf '%s\n' "$OLD_IMAGE_ID";
  elif [[ "$5" == "astranull-control-plane:$SAME_SHA" ]]; then cat "$TAG_FILE";
  else exit 91; fi
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ "$3" == "$OLD_IMAGE_ID" && "$4" == "astranull-control-plane:$SAME_SHA" ]]
  printf '%s\n' "$OLD_IMAGE_ID" > "$TAG_FILE"
elif [[ "$1" == inspect && "$3" == '{{.Config.Image}}' && "$4" == control-cid ]]; then
  cat "$CONTAINER_FILE"
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
        CORE_WORKER_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/core-worker-image-state"
        persist_control_plane_image_state "$same_sha" "$OLD_IMAGE_ID"
        persist_core_worker_image_state "$same_sha" "$OLD_IMAGE_ID"
        printf '%s\n' "$OLD_IMAGE_ID" > "$TAG_FILE"
        build_control_plane_from_commit "$same_sha"
        [[ "$(cat "$TAG_FILE")" == "$REBUILT_IMAGE_ID" ]] || exit 93

        MODE=deploy
        previous="$same_sha"
        SHA="$same_sha"
        previous_control_plane_tag="$same_sha"
        previous_control_plane_image_id="$OLD_IMAGE_ID"
        previous_core_worker_tag="$same_sha"
        previous_core_worker_image_id="$OLD_IMAGE_ID"
        previous_compose="$DUMMY_COMPOSE"
        target_compose="$DUMMY_COMPOSE"
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        had_current_release=1
        previous_release_validator_tag="${'8'.repeat(40)}"
        previous_release_validator_image_id="sha256:${'9'.repeat(64)}"
        migration_started=1
        cleanup_active_operation_containers_checked() { :; }
        cleanup_backup_orphans() { :; }
        write_pending_release_bundle() { printf 'journal|%s\n' "$*" >> "\${CALL_LOG:-/dev/null}"; }
        promote_pending_release_bundle() { printf 'promote\n' >> "\${CALL_LOG:-/dev/null}"; }
        cleanup_compose_snapshots() { :; }
        git() { [[ "$*" == "checkout -q --detach $same_sha" ]]; }
        start_core_stack() { cat "$TAG_FILE" > "$CONTAINER_FILE"; }
        compose_timeout() {
          if [[ "$*" == '30 ps -q control-plane' ]]; then
            printf control-cid
          else
            return 94
          fi
        }
        check_control_plane() { :; }
        check_core_workers() { :; }
        verify_workers_image_tag() { [[ "$1" == "$same_sha" && "$2" == "$OLD_IMAGE_ID" ]]; }
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
      assert.equal(readFileSync(path.join(temp, 'state/core-worker-image-state'), 'utf8'), `${sameSha}\n${oldImageId}\n`);
      const calls = readFileSync(callLog, 'utf8');
      assert.match(calls, /build --iidfile \S+\/\.astranull-build-iid\.[A-Za-z0-9]{6} -f ops\/aws\/Dockerfile -t astranull-control-plane:[0-9a-f]{40} -/);
      assert.match(calls, new RegExp(`image tag ${oldImageId} astranull-control-plane:[0-9a-f]{40}`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('keeps the current validator usable and cannot report rollback success after state-write failure', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-validator-rollback-state-'));
    const validatorState = path.join(temp, 'release-validator-image-state');
    const validatorTag = 'e'.repeat(40);
    const validatorImageId = `sha256:${'f'.repeat(64)}`;
    const originalValidatorState = `${validatorTag}\n${validatorImageId}\n`;
    writeFileSync(validatorState, originalValidatorState, { mode: 0o600 });
    try {
      const rollback = runBash(`
        source "$1"
        MODE=deploy
        previous="${'1'.repeat(40)}"
        SHA="${'2'.repeat(40)}"
        previous_control_plane_tag="${'1'.repeat(40)}"
        previous_control_plane_image_id="sha256:${'3'.repeat(64)}"
        previous_core_worker_tag="${'1'.repeat(40)}"
        previous_core_worker_image_id="sha256:${'3'.repeat(64)}"
        previous_connector_enabled=0
        previous_compose=/tmp/validator-rollback.previous.yml
        target_compose=/tmp/validator-rollback.target.yml
        validated_connector_mode=disabled
        plain_host=''
        backup=/safe/predeploy.dump.enc
        activated=1
        had_current_release=1
        previous_release_validator_tag="${'8'.repeat(40)}"
        previous_release_validator_image_id="sha256:${'9'.repeat(64)}"
        migration_started=1
        cleanup_active_operation_containers_checked() { :; }
        cleanup_backup_orphans() { :; }
        write_pending_release_bundle() { printf 'journal|%s\n' "$*" >> "\${CALL_LOG:-/dev/null}"; }
        promote_pending_release_bundle() { printf 'promote\n' >> "\${CALL_LOG:-/dev/null}"; }
        cleanup_compose_snapshots() { :; }
        git() { :; }
        rebind_control_plane_image_tag() { :; }
        rebind_core_worker_image_tag() { :; }
        start_core_stack() { :; }
        check_control_plane() { :; }
        check_core_workers() { :; }
        verify_control_plane_image_tag() { :; }
        verify_workers_image_tag() { :; }
        promote_pending_release_bundle() { return 81; }
        persist_control_plane_image_state() { exit 97; }
        persist_core_worker_image_state() { exit 98; }
        persist_release_validator_image_state() { exit 99; }
        fail_closed_runtime() { echo fail-closed-runtime >&2; }
        rollback_on_error 73
      `);
      assert.equal(rollback.status, 73, rollback.stderr);
      assert.match(rollback.stderr, /automatic rollback failed/);
      assert.match(rollback.stderr, /fail-closed-runtime/);
      assert.doesNotMatch(rollback.stderr, /automatic hybrid rollback restored/);
      assert.equal(readFileSync(validatorState, 'utf8'), originalValidatorState);

      const reload = runBash(`
        source "$1"
        RELEASE_VALIDATOR_IMAGE_STATE_FILE="$VALIDATOR_STATE"
        image_id_for_ref() { printf '%s\\n' "$VALIDATOR_IMAGE_ID"; }
        timeout() { return 0; }
        load_release_validator_image_identity
        printf '%s|%s' "$release_validator_tag" "$release_validator_image_id"
      `, {
        VALIDATOR_IMAGE_ID: validatorImageId,
        VALIDATOR_STATE: validatorState,
      });
      assert.equal(reload.status, 0, reload.stderr);
      assert.equal(reload.stdout, `${validatorTag}|${validatorImageId}`);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('fails missing validator state before backup or outage work can run', () => {
    for (const [name, script] of [['deploy', DEPLOY], ['restore', RESTORE]]) {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-${name}-missing-validator-`));
      const marker = path.join(temp, 'outage-marker');
      try {
        const result = runBash(`
          source "$1"
          RELEASE_VALIDATOR_IMAGE_STATE_FILE="$MISSING_STATE"
          backup_database() { : > "$OUTAGE_MARKER"; }
          stop_remove_services() { : > "$OUTAGE_MARKER"; }
          set +e
          load_release_validator_image_identity
          rc=$?
          set -e
          printf '%s|%s' "$rc" "$([[ -e "$OUTAGE_MARKER" ]] && printf touched || printf untouched)"
        `, {
          MISSING_STATE: path.join(temp, 'missing-release-validator-image-state'),
          OUTAGE_MARKER: marker,
        }, script);
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /^[1-9][0-9]*\|untouched$/);
        assert.match(result.stderr, /requires.*release validator state|release validator state.*required/i);
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
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
if [[ "$1" == build ]]; then
  printf '%s\\n' "$@" > "$FAKE_DOCKER_ARGS"
  args=("$@")
  iid_file=''
  for ((i=0; i<\${#args[@]}; i++)); do
    [[ "\${args[$i]}" != --iidfile ]] || iid_file="\${args[$((i+1))]}"
  done
  [[ -n "$iid_file" && "\${!#}" == - ]]
  printf '%s\\n' "$EXPECTED_IMAGE_ID" > "$iid_file"
  tar -tf - > "$FAKE_DOCKER_TAR_LIST"
elif [[ "$1 $2" == 'image inspect' && "$5" == astranull-control-plane:* ]]; then
  printf '%s\\n' "$EXPECTED_IMAGE_ID"
else
  exit 97
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        tested_sha=$(git rev-parse HEAD)
        build_control_plane_from_commit "$tested_sha"
        printf 'tested-sha=%s' "$tested_sha"
      `, {
        EXPECTED_IMAGE_ID: `sha256:${'d'.repeat(64)}`,
        FAKE_DOCKER_ARGS: argsFile,
        FAKE_DOCKER_TAR_LIST: tarList,
        PATH: `${temp}:${process.env.PATH}`,
      });
      assert.equal(result.status, 0, result.stderr);
      const testedSha = result.stdout.replace('tested-sha=', '');
      assert.match(testedSha, /^[0-9a-f]{40}$/);
      const buildArgs = readFileSync(argsFile, 'utf8').trim().split('\n');
      assert.equal(buildArgs[0], 'build');
      assert.equal(buildArgs[1], '--iidfile');
      assert.equal(path.dirname(buildArgs[2]), SHELL_BACKUP_DIR);
      assert.match(path.basename(buildArgs[2]), /^\.astranull-build-iid\.[A-Za-z0-9]{6}$/);
      assert.deepEqual(buildArgs.slice(3), [
        '-f',
        'ops/aws/Dockerfile',
        '-t',
        `astranull-control-plane:${testedSha}`,
        '-',
      ]);
      assert.equal(existsSync(buildArgs[2]), false, 'iidfile must be removed after capture');
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

  it('atomically persists durable control, core, connector, and validator identities outside the checkout', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-deploy-state-'));
    const tag = 'a'.repeat(40);
    const coreTag = 'b'.repeat(40);
    const connectorTag = 'c'.repeat(40);
    const validatorTag = 'd'.repeat(40);
    const imageId = `sha256:${'5'.repeat(64)}`;
    const coreImageId = `sha256:${'7'.repeat(64)}`;
    const connectorImageId = `sha256:${'6'.repeat(64)}`;
    const validatorImageId = `sha256:${'8'.repeat(64)}`;
    try {
      const result = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/connector-image-state"
        RELEASE_VALIDATOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/release-validator-image-state"
        persist_control_plane_image_state "$EXPECTED_TAG" "$EXPECTED_IMAGE_ID"
        persist_core_worker_image_state "$CORE_TAG" "$CORE_IMAGE_ID"
        persist_connector_image_state "$CONNECTOR_TAG" "$CONNECTOR_IMAGE_ID"
        persist_release_validator_image_state "$VALIDATOR_TAG" "$VALIDATOR_IMAGE_ID"
        printf '%s|%s|%s|%s|%s|%s|%s|%s' \
          "$(read_control_plane_image_tag "${'d'.repeat(40)}")" \
          "$(read_control_plane_image_id)" \
          "$(read_core_worker_image_tag)" \
          "$(read_core_worker_image_id)" \
          "$(read_connector_image_tag)" \
          "$(read_connector_image_id)" \
          "$(read_release_validator_image_tag)" \
          "$(read_release_validator_image_id)"
      `, {
        STATE_DIR: temp,
        EXPECTED_IMAGE_ID: imageId,
        EXPECTED_TAG: tag,
        CORE_IMAGE_ID: coreImageId,
        CORE_TAG: coreTag,
        CONNECTOR_IMAGE_ID: connectorImageId,
        CONNECTOR_TAG: connectorTag,
        VALIDATOR_IMAGE_ID: validatorImageId,
        VALIDATOR_TAG: validatorTag,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(
        result.stdout,
        `${tag}|${imageId}|${coreTag}|${coreImageId}|${connectorTag}|${connectorImageId}|${validatorTag}|${validatorImageId}`,
      );
      const stateFile = path.join(temp, 'control-plane-image-tag');
      const coreStateFile = path.join(temp, 'core-worker-image-state');
      const connectorStateFile = path.join(temp, 'connector-image-state');
      const validatorStateFile = path.join(temp, 'release-validator-image-state');
      assert.equal(readFileSync(stateFile, 'utf8'), `${tag}\n${imageId}\n`);
      assert.equal(readFileSync(coreStateFile, 'utf8'), `${coreTag}\n${coreImageId}\n`);
      assert.equal(readFileSync(connectorStateFile, 'utf8'), `${connectorTag}\n${connectorImageId}\n`);
      assert.equal(readFileSync(validatorStateFile, 'utf8'), `${validatorTag}\n${validatorImageId}\n`);
      for (const file of [stateFile, coreStateFile, connectorStateFile, validatorStateFile]) {
        assert.equal(statSync(file).mode & 0o777, 0o600);
        assert.equal(file.startsWith(ROOT), false);
      }
      assert.equal(statSync(temp).mode & 0o777, 0o700);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
  it('preserves every original image-state file byte-for-byte when any atomic write step fails', () => {
    const states = [
      ['control-plane-image-tag', 'persist_control_plane_image_state'],
      ['core-worker-image-state', 'persist_core_worker_image_state'],
      ['connector-image-state', 'persist_connector_image_state'],
      ['release-validator-image-state', 'persist_release_validator_image_state'],
    ];
    const steps = ['mkdir', 'chmod-dir', 'mktemp', 'printf', 'chmod-file', 'atomic-rename', 'atomic-noop'];
    const oldTag = '1'.repeat(40);
    const oldImageId = `sha256:${'2'.repeat(64)}`;
    const newTag = '3'.repeat(40);
    const newImageId = `sha256:${'4'.repeat(64)}`;
    const original = `${oldTag}\n${oldImageId}\n`;

    for (const [filename, persistFunction] of states) {
      for (const step of steps) {
        const temp = mkdtempSync(path.join(tmpdir(), 'astranull-state-fault-'));
        const destination = path.join(temp, filename);
        writeFileSync(destination, original, { mode: 0o600 });
        try {
          const result = runBash(`
            source "$1"
            DEPLOY_STATE_DIR="$STATE_DIR"
            CONTROL_PLANE_IMAGE_TAG_FILE="$DEPLOY_STATE_DIR/control-plane-image-tag"
            CORE_WORKER_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/core-worker-image-state"
            CONNECTOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/connector-image-state"
            RELEASE_VALIDATOR_IMAGE_STATE_FILE="$DEPLOY_STATE_DIR/release-validator-image-state"
            mkdir() { [[ "$FAULT_STEP" != mkdir ]] || return 71; command mkdir "$@"; }
            chmod() {
              [[ ! ( "$FAULT_STEP" == chmod-dir && "$1" == 700 ) ]] || return 72
              [[ ! ( "$FAULT_STEP" == chmod-file && "$1" == 600 ) ]] || return 73
              command chmod "$@"
            }
            mktemp() { [[ "$FAULT_STEP" != mktemp ]] || return 74; command mktemp "$@"; }
            printf() { [[ "$FAULT_STEP" != printf ]] || return 75; builtin printf "$@"; }
            release_state_atomic_rename() {
              [[ "$FAULT_STEP" != atomic-rename ]] || return 76
              [[ "$FAULT_STEP" != atomic-noop ]] || return 0
              command python3 - "$1" "$2" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
PY
            }
            set +e
            "$PERSIST_FUNCTION" "$NEW_TAG" "$NEW_IMAGE_ID"
            rc=$?
            set -e
            echo "$rc"
          `, {
            FAULT_STEP: step,
            NEW_IMAGE_ID: newImageId,
            NEW_TAG: newTag,
            PERSIST_FUNCTION: persistFunction,
            STATE_DIR: temp,
          });
          assert.equal(result.status, 0, result.stderr);
          assert.notEqual(result.stdout.trim(), '0', `${filename} ${step} must fail`);
          assert.equal(readFileSync(destination, 'utf8'), original, `${filename} ${step}`);
          assert.deepEqual(readdirSync(temp), [filename], `${filename} ${step} leaked a temp file`);
        } finally {
          rmSync(temp, { recursive: true, force: true });
        }
      }
    }
  });

  it('uses one canonical bundle and self-recovers pending/current/projection SIGKILL boundaries', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-canonical-recovery-'));
    const stateDir = path.join(temp, 'state');
    const current = path.join(stateDir, 'release-image-current');
    const pending = path.join(stateDir, 'release-image-pending');
    const controlProjection = path.join(stateDir, 'control-plane-image-tag');
    const coreProjection = path.join(stateDir, 'core-worker-image-state');
    const validatorProjection = path.join(stateDir, 'release-validator-image-state');
    const aTag = '1'.repeat(40);
    const bTag = '2'.repeat(40);
    const cTag = '3'.repeat(40);
    const dTag = '4'.repeat(40);
    const aId = `sha256:${'a'.repeat(64)}`;
    const bId = `sha256:${'b'.repeat(64)}`;
    const cId = `sha256:${'c'.repeat(64)}`;
    const dId = `sha256:${'d'.repeat(64)}`;
    const env = {
      A_ID: aId, A_TAG: aTag, B_ID: bId, B_TAG: bTag,
      C_ID: cId, C_TAG: cTag, D_ID: dId, D_TAG: dTag,
      STATE_DIR: stateDir,
    };
    const setup = `
      DEPLOY_STATE_DIR="$STATE_DIR"
      CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
      PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
      CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
      CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
      CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
      RELEASE_VALIDATOR_IMAGE_STATE_FILE="$STATE_DIR/release-validator-image-state"
      release_runtime_matches_bundle_file() { return 1; }
      release_runtime_matches_bundle_file_for_legacy_migration() { return 1; }
      release_runtime_services_absent() { return 0; }
    `;
    try {
      const initialized = runBash(`
        source "$1"
        ${setup}
        write_current_release_bundle_for_migration "$A_TAG" "$A_ID" "$A_TAG" "$A_ID" "$A_TAG" "$A_ID" 0 '' ''
      `, env);
      assert.equal(initialized.status, 0, initialized.stderr);
      assert.match(readFileSync(current, 'utf8'), /^schema=astranull\.release-image-bundle\nversion=1\n/);

      const killedAfterCurrentRename = runBash(`
        source "$1"
        ${setup}
        write_pending_release_bundle "$B_TAG" "$B_ID" "$B_TAG" "$B_ID" "$B_TAG" "$B_ID" 0 '' ''
        regenerate_release_state_projections() { kill -KILL $$; }
        promote_pending_release_bundle
      `, env);
      assert.equal(killedAfterCurrentRename.status, 137, killedAfterCurrentRename.stderr);
      assert.equal(existsSync(pending), false, 'atomic promotion consumes pending before projection repair');
      assert.match(readFileSync(current, 'utf8'), new RegExp(`control_tag=${bTag}`));

      writeFileSync(controlProjection, `${aTag}\n${aId}\n`, { mode: 0o600 });
      const repairedAfterPromotion = runBash(`
        source "$1"
        ${setup}
        reconcile_pending_release_bundle
        printf '%s|%s' "$(read_control_plane_image_tag)" "$(read_release_validator_image_id)"
      `, env);
      assert.equal(repairedAfterPromotion.status, 0, repairedAfterPromotion.stderr);
      assert.equal(repairedAfterPromotion.stdout, `${bTag}|${bId}`);
      assert.equal(readFileSync(controlProjection, 'utf8'), `${bTag}\n${bId}\n`);

      const killedAfterActivation = runBash(`
        source "$1"
        ${setup}
        write_pending_release_bundle "$C_TAG" "$C_ID" "$C_TAG" "$C_ID" "$C_TAG" "$C_ID" 0 '' ''
        kill -KILL $$
      `, env);
      assert.equal(killedAfterActivation.status, 137, killedAfterActivation.stderr);
      assert.equal(existsSync(pending), true);
      const promotedOnRestart = runBash(`
        source "$1"
        ${setup}
        release_runtime_matches_bundle_file() { release_bundle_load "$1" && [[ "$release_bundle_control_tag" == "$C_TAG" ]]; }
        release_runtime_health_for_bundle_file() { :; }
        reconcile_pending_release_bundle
        printf '%s' "$(read_control_plane_image_tag)"
      `, env);
      assert.equal(promotedOnRestart.status, 0, promotedOnRestart.stderr);
      assert.equal(promotedOnRestart.stdout, cTag);
      assert.equal(existsSync(pending), false);

      const killedWithRuntimeStillCurrent = runBash(`
        source "$1"
        ${setup}
        write_pending_release_bundle "$D_TAG" "$D_ID" "$D_TAG" "$D_ID" "$D_TAG" "$D_ID" 0 '' ''
        kill -KILL $$
      `, env);
      assert.equal(killedWithRuntimeStillCurrent.status, 137, killedWithRuntimeStillCurrent.stderr);
      const discardedOnRestart = runBash(`
        source "$1"
        ${setup}
        release_runtime_matches_bundle_file() { release_bundle_load "$1" && [[ "$release_bundle_control_tag" == "$C_TAG" ]]; }
        release_runtime_health_for_bundle_file() { :; }
        reconcile_pending_release_bundle
        printf '%s' "$(read_control_plane_image_tag)"
      `, env);
      assert.equal(discardedOnRestart.status, 0, discardedOnRestart.stderr);
      assert.equal(discardedOnRestart.stdout, cTag);
      assert.equal(existsSync(pending), false);

      const killedAfterOneProjection = runBash(`
        source "$1"
        ${setup}
        persist_control_plane_image_state "$D_TAG" "$D_ID"
        kill -KILL $$
      `, env);
      assert.equal(killedAfterOneProjection.status, 137, killedAfterOneProjection.stderr);
      assert.equal(readFileSync(controlProjection, 'utf8'), `${dTag}\n${dId}\n`);
      const projectionRepaired = runBash(`
        source "$1"
        ${setup}
        reconcile_pending_release_bundle
      `, env);
      assert.equal(projectionRepaired.status, 0, projectionRepaired.stderr);
      assert.equal(readFileSync(controlProjection, 'utf8'), `${cTag}\n${cId}\n`);
      assert.equal(readFileSync(coreProjection, 'utf8'), `${cTag}\n${cId}\n`);
      assert.equal(readFileSync(validatorProjection, 'utf8'), `${cTag}\n${cId}\n`);

      const mixed = runBash(`
        source "$1"
        ${setup}
        write_pending_release_bundle "$D_TAG" "$D_ID" "$D_TAG" "$D_ID" "$D_TAG" "$D_ID" 0 '' ''
        release_runtime_matches_bundle_file() { return 1; }
        reconcile_pending_release_bundle
      `, env);
      assert.notEqual(mixed.status, 0);
      assert.match(mixed.stderr, /mixed or matches neither/);
      assert.equal(existsSync(pending), true, 'ambiguous journal must remain for fail-closed investigation');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('recovers only exact immutable-current legacy residue and remains retry-safe without pending', () => {
    const currentTag = '6'.repeat(40);
    const targetTag = 'd'.repeat(40);
    const currentId = `sha256:${'6'.repeat(64)}`;
    const targetId = `sha256:${'d'.repeat(64)}`;

    const runScenario = ({
      connectorEnabled = false,
      variant = 'safe',
      failProjection = false,
      failRemove = false,
      secondVariant = variant,
      failSecondProjection = false,
      failSecondHealth = false,
      script = DEPLOY,
    }) => {
      const temp = mkdtempSync(path.join(tmpdir(), `astranull-legacy-pending-${variant}-`));
      const stateDir = path.join(temp, 'state');
      const result = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
        PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
        RELEASE_VALIDATOR_IMAGE_STATE_FILE="$STATE_DIR/release-validator-image-state"

        write_release_bundle_atomic "$CURRENT_RELEASE_BUNDLE_FILE" \
          "$CURRENT_TAG" "$CURRENT_ID" "$CURRENT_TAG" "$CURRENT_ID" \
          "$TARGET_TAG" "$TARGET_ID" "$CONNECTOR_ENABLED" \
          "$([[ "$CONNECTOR_ENABLED" == 1 ]] && printf %s "$CURRENT_TAG")" \
          "$([[ "$CONNECTOR_ENABLED" == 1 ]] && printf %s "$CURRENT_ID")"
        write_pending_release_bundle \
          "$TARGET_TAG" "$TARGET_ID" "$TARGET_TAG" "$TARGET_ID" \
          "$TARGET_TAG" "$TARGET_ID" "$CONNECTOR_ENABLED" \
          "$([[ "$CONNECTOR_ENABLED" == 1 ]] && printf %s "$TARGET_TAG")" \
          "$([[ "$CONNECTOR_ENABLED" == 1 ]] && printf %s "$TARGET_ID")"

        # Reproduce a crash/failure-era mixed projection: canonical is authoritative,
        # while compatibility files contain a blend of target and current identities.
        persist_control_plane_image_state "$TARGET_TAG" "$TARGET_ID"
        persist_core_worker_image_state "$CURRENT_TAG" "$CURRENT_ID"
        persist_release_validator_image_state "$TARGET_TAG" "$TARGET_ID"
        persist_connector_image_state "$TARGET_TAG" "$TARGET_ID"

        compose_timeout() {
          local service="\${!#}"
          case "$*" in
            '30 ps -q '*|'30 ps --all -q '*)
              case "$service" in
                postgres|caddy)
                  [[ ! ( "$VARIANT" == missing-runtime && "$service" == caddy ) ]] \
                    && printf '%s-cid' "$service"
                  return 0
                  ;;
                control-plane|probe-worker|password-recovery-worker|test-policy-runner)
                  [[ ! ( "$VARIANT" == missing && "$service" == test-policy-runner ) ]] \
                    && printf '%s-cid' "$service"
                  return 0
                  ;;
                connector-poll-scheduler|connector-poll-runner)
                  if [[ "$CONNECTOR_ENABLED" == 1 ]]; then
                    [[ ! ( "$VARIANT" == missing-connector && "$service" == connector-poll-runner ) ]] \
                      && printf '%s-cid' "$service"
                  elif [[ "$VARIANT" == unexpected-disabled-connector ]]; then
                    printf '%s-cid' "$service"
                  fi
                  return 0
                  ;;
                *) return 90 ;;
              esac
              ;;
            *) return 91 ;;
          esac
        }
        timeout() {
          [[ "\${1:-}" == -k ]] && shift 3
          [[ "$1 $2 $3" == 'docker inspect --format' ]] || return 92
          local format=$4 cid=$5 service="\${5%-cid}" tag="$CURRENT_TAG" image_id="$CURRENT_ID"
          local image_name=astranull-control-plane
          if [[ "$VARIANT" == tag-only ]]; then
            image_id="$TARGET_ID"
          elif [[ "$VARIANT" == mixed && "$service" == probe-worker ]]; then
            tag="$TARGET_TAG"
            image_id="$TARGET_ID"
          elif [[ "$VARIANT" == wrong-config-ref && "$service" == probe-worker ]]; then
            image_name=untrusted-control-plane
          elif [[ "$service" == connector-poll-scheduler || "$service" == connector-poll-runner ]]; then
            tag="$CURRENT_TAG"
            image_id="$CURRENT_ID"
          fi
          case "$format" in
            '{{.Config.Image}}') printf '%s:%s' "$image_name" "$tag" ;;
            '{{.Image}}') printf '%s' "$image_id" ;;
            *) return 93 ;;
          esac
        }
        check_postgres() { :; }
        check_control_plane() { :; }
        check_core_workers() { :; }
        check_connector_workers() { :; }
        verify_services_absent() { release_runtime_services_absent "$@"; }
        stop_remove_services() { VARIANT=safe; }
        if [[ "$FAIL_PROJECTION" == 1 ]]; then
          persist_core_worker_image_state() { return 78; }
        fi
        if [[ "$FAIL_REMOVE" == 1 ]]; then
          release_state_durable_remove() { return 79; }
        fi

        set +e
        reconcile_pending_release_bundle
        first_rc=$?
        second_rc=skipped
        if ((first_rc == 0)); then
          VARIANT="$SECOND_VARIANT"
          if [[ "$FAIL_SECOND_PROJECTION" == 1 ]]; then
            persist_core_worker_image_state() { return 78; }
          fi
          if [[ "$FAIL_SECOND_HEALTH" == 1 ]]; then
            check_control_plane() { return 77; }
          fi
          reconcile_pending_release_bundle
          second_rc=$?
        fi
        set -e
        printf '%s|%s|%s|%s|%s|%s' \
          "$first_rc" \
          "$second_rc" \
          "$([[ -e "$PENDING_RELEASE_BUNDLE_FILE" ]] && printf present || printf absent)" \
          "$([[ -e "$CONNECTOR_IMAGE_STATE_FILE" ]] && printf present || printf absent)" \
          "$([[ -e "$CONTROL_PLANE_IMAGE_TAG_FILE" ]] && head -n 1 "$CONTROL_PLANE_IMAGE_TAG_FILE" || printf missing)" \
          "$([[ -e "$CORE_WORKER_IMAGE_STATE_FILE" ]] && head -n 1 "$CORE_WORKER_IMAGE_STATE_FILE" || printf missing)"
      `, {
        CONNECTOR_ENABLED: connectorEnabled ? '1' : '0',
        CURRENT_ID: currentId,
        CURRENT_TAG: currentTag,
        FAIL_PROJECTION: failProjection ? '1' : '0',
        FAIL_REMOVE: failRemove ? '1' : '0',
        FAIL_SECOND_HEALTH: failSecondHealth ? '1' : '0',
        FAIL_SECOND_PROJECTION: failSecondProjection ? '1' : '0',
        SECOND_VARIANT: secondVariant,
        STATE_DIR: stateDir,
        TARGET_ID: targetId,
        TARGET_TAG: targetTag,
        VARIANT: variant,
      }, script);
      return { result, temp };
    };

    const scenarios = [
      { name: 'disabled-safe', options: {}, success: true, connectorProjection: 'absent' },
      { name: 'enabled-safe', options: { connectorEnabled: true }, success: true, connectorProjection: 'present' },
      { name: 'restore-disabled-safe', options: { script: RESTORE }, success: true, connectorProjection: 'absent' },
      {
        name: 'no-pending-mixed-activation',
        options: { secondVariant: 'mixed' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-matching-tags-with-wrong-ids',
        options: { secondVariant: 'tag-only' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-wrong-config-reference',
        options: { secondVariant: 'wrong-config-ref' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-missing-runtime',
        options: { secondVariant: 'missing-runtime' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-missing-core',
        options: { secondVariant: 'missing' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-missing-enabled-connector',
        options: { connectorEnabled: true, secondVariant: 'missing-connector' },
        success: true,
        secondFailure: true,
        connectorProjection: 'present',
      },
      {
        name: 'no-pending-unexpected-disabled-connectors',
        options: { secondVariant: 'unexpected-disabled-connector' },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-health-failure',
        options: { failSecondHealth: true },
        success: true,
        secondFailure: true,
      },
      {
        name: 'no-pending-projection-write-failure',
        options: { failSecondProjection: true },
        success: true,
        secondFailure: true,
      },
      { name: 'mixed-activation', options: { variant: 'mixed' }, success: false },
      { name: 'matching-tags-with-wrong-ids', options: { variant: 'tag-only' }, success: false },
      { name: 'missing-core', options: { variant: 'missing' }, success: false },
      {
        name: 'missing-enabled-connector',
        options: { connectorEnabled: true, variant: 'missing-connector' },
        success: false,
      },
      {
        name: 'unexpected-disabled-connectors',
        options: { variant: 'unexpected-disabled-connector' },
        success: false,
      },
      {
        name: 'atomic-projection-write-failure',
        options: { connectorEnabled: true, failProjection: true },
        success: false,
        writeFailure: true,
      },
      {
        name: 'durable-remove-failure',
        options: { connectorEnabled: true, failRemove: true },
        success: false,
        writeFailure: true,
      },
    ];

    for (const scenario of scenarios) {
      const { result, temp } = runScenario(scenario.options);
      try {
        assert.equal(result.status, 0, `${scenario.name}: ${result.stderr}`);
        const [firstRc, secondRc, pending, connectorProjection, controlProjection, coreProjection] = result.stdout.split('|');
        if (scenario.success) {
          assert.equal(firstRc, '0', `${scenario.name}: ${result.stderr}`);
          if (scenario.secondFailure) {
            assert.notEqual(secondRc, '0', `${scenario.name} second reconciliation must fail closed`);
          } else {
            assert.equal(secondRc, '0', `${scenario.name}: ${result.stderr}`);
          }
          assert.equal(pending, 'absent', scenario.name);
          assert.equal(connectorProjection, scenario.connectorProjection ?? 'absent', scenario.name);
          assert.equal(controlProjection, currentTag, scenario.name);
          assert.equal(coreProjection, currentTag, scenario.name);
          assert.match(result.stderr, /immutable IDs still match canonical current state/);
        } else {
          assert.notEqual(firstRc, '0', scenario.name);
          assert.equal(secondRc, 'skipped', scenario.name);
          assert.equal(pending, 'present', `${scenario.name} must preserve pending evidence`);
          if (!scenario.writeFailure) {
            assert.match(result.stderr, /mixed or matches neither/, scenario.name);
          }
        }
      } finally {
        rmSync(temp, { recursive: true, force: true });
      }
    }
  });

  it('inspects the complete raw-ID runtime before reconciling a bundle', () => {
    const controlId = `sha256:${'1'.repeat(64)}`;
    const coreId = `sha256:${'2'.repeat(64)}`;
    const connectorId = `sha256:${'3'.repeat(64)}`;
    const result = runBash(`
      source "$1"
      release_bundle_control_image_id="$CONTROL_ID"
      release_bundle_core_image_id="$CORE_ID"
      release_bundle_connector_enabled=1
      release_bundle_connector_image_id="$CONNECTOR_ID"
      compose_timeout() {
        service="\${!#}"
        case "$*" in
          '30 ps -q '*|'30 ps --all -q '*) printf '%s-cid' "$service" ;;
          *) return 90 ;;
        esac
      }
      timeout() {
        cid="\${!#}"
        service="\${cid%-cid}"
        case "$service" in
          control-plane) expected="$CONTROL_ID" ;;
          probe-worker|password-recovery-worker|test-policy-runner) expected="$CORE_ID" ;;
          connector-poll-scheduler|connector-poll-runner) expected="$CONNECTOR_ID" ;;
          *) return 91 ;;
        esac
        printf '%s' "$expected"
      }
      release_runtime_matches_loaded_bundle
    `, { CONNECTOR_ID: connectorId, CONTROL_ID: controlId, CORE_ID: coreId });
    assert.equal(result.status, 0, result.stderr);

    const mixed = runBash(`
      source "$1"
      release_bundle_control_image_id="$CONTROL_ID"
      release_bundle_core_image_id="$CORE_ID"
      release_bundle_connector_enabled=0
      release_bundle_connector_image_id=''
      compose_timeout() {
        service="\${!#}"
        case "$*" in
          '30 ps -q '*|'30 ps --all -q '*)
            if [[ "$service" == connector-poll-runner ]]; then printf stale-cid; else printf '%s-cid' "$service"; fi ;;
          *) return 90 ;;
        esac
      }
      timeout() { printf '%s' "$CORE_ID"; }
      release_runtime_matches_loaded_bundle
    `, { CONTROL_ID: controlId, CORE_ID: coreId });
    assert.notEqual(mixed.status, 0, 'disabled connector state must reject any stopped or running connector container');
  });

  it('rejects a pre-existing hard-linked plaintext path before pg_dump and checks deletion links', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-plaintext-hardlink-'));
    const backupDir = path.join(temp, 'backups');
    const original = path.join(backupDir, 'original');
    const linked = path.join(backupDir, '.astranull-plaintext.deploy.aB3dE6');
    mkdirSync(backupDir, { mode: 0o700 });
    writeFileSync(original, '', { mode: 0o600 });
    linkSync(original, linked);
    try {
      const result = runBash(`
        source "$1"
        BACKUP_DIR="$BACKUP_DIR_FIXTURE"
        mktemp() { printf '%s\n' "$LINKED_PATH"; }
        compose_ops_run() { : > "$PG_DUMP_MARKER"; }
        set +e
        allocate_plaintext_backup
        rc=$?
        set -e
        printf '%s|%s' "$rc" "$([[ -e "$PG_DUMP_MARKER" ]] && printf wrote || printf untouched)"
      `, {
        BACKUP_DIR_FIXTURE: backupDir,
        LINKED_PATH: linked,
        PG_DUMP_MARKER: path.join(temp, 'pg-dump-ran'),
      });
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /^[1-9][0-9]*\|untouched$/);
      assert.match(result.stderr, /link count is 2.*hard-link exposure/);

      const deletion = runBash(`
        source "$1"
        set +e
        delete_plaintext_checked "$LINKED_PATH"
        rc=$?
        set -e
        printf '%s|%s' "$rc" "$([[ -e "$LINKED_PATH" ]] && printf present || printf absent)"
      `, { LINKED_PATH: linked });
      assert.equal(deletion.status, 0, deletion.stderr);
      assert.match(deletion.stdout, /^[1-9][0-9]*\|absent$/);
      assert.match(deletion.stderr, /link count is 2/);
      assert.equal(existsSync(original), true, 'hard-link anomaly must remain an escalated exposure even after path deletion');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('uses a random exclusive restore plaintext path and escalates stale hard links', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-plaintext-'));
    const backupDir = path.join(temp, 'backups');
    mkdirSync(backupDir, { mode: 0o700 });
    try {
      const allocated = runBash(`
        source "$1"
        BACKUP_DIR="$BACKUP_DIR_FIXTURE"
        cleanup_stale_plaintext_archives
        allocate_restore_plaintext_path
        printf '%s|%s' "\${plain_host##*/}" "$([[ -e "$plain_host" || -L "$plain_host" ]] && printf present || printf absent)"
      `, { BACKUP_DIR_FIXTURE: backupDir }, RESTORE);
      assert.equal(allocated.status, 0, allocated.stderr);
      assert.match(allocated.stdout, /^\.astranull-plaintext\.restore\.[A-Za-z0-9]{6}\|absent$/);

      const original = path.join(backupDir, 'stolen-restore-plaintext');
      const linked = path.join(backupDir, '.astranull-plaintext.restore.aB3dE6');
      writeFileSync(original, 'sensitive', { mode: 0o600 });
      linkSync(original, linked);
      const cleanup = runBash(`
        source "$1"
        BACKUP_DIR="$BACKUP_DIR_FIXTURE"
        set +e
        cleanup_stale_plaintext_archives
        rc=$?
        set -e
        printf '%s|%s' "$rc" "$([[ -e "$LINKED_PATH" ]] && printf present || printf absent)"
      `, { BACKUP_DIR_FIXTURE: backupDir, LINKED_PATH: linked }, RESTORE);
      assert.equal(cleanup.status, 0, cleanup.stderr);
      assert.match(cleanup.stdout, /^[1-9][0-9]*\|absent$/);
      assert.match(cleanup.stderr, /link count is 2.*hard-link exposure/);
      assert.equal(existsSync(original), true, 'unknown hard link must remain an escalated exposure');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('preserves non-scratch backup names and prunes only inventoried current pairs', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-backup-retention-'));
    chmodSync(temp, 0o700);
    const valid = [
      'postgres-2026-01-01T00-00-00-000Z-aaaaaaaaaaaa.dump.enc',
      'postgres-2026-01-02T00-00-00-000Z-bbbbbbbbbbbb.dump.enc',
    ];
    const productionLegacy = 'postgres-2026-08-30T16-47-04-492Z.dump.enc';
    const manifestlessLegacy = 'postgres-2026-08-29T16-47-04-492Z.dump.enc';
    const unknownManifest = 'operator-copy.dump.enc.manifest.json';
    const impossibleFinals = [
      'postgres-2026-13-01T00-00-00-000Z-111111111111.dump.enc',
      'postgres-2026-04-31T00-00-00-000Z-222222222222.dump.enc',
      'postgres-2025-02-29T00-00-00-000Z.dump.enc',
      'postgres-2026-01-01T24-00-00-000Z-333333333333.dump.enc',
      'postgres-2026-01-01T00-60-00-000Z.dump.enc',
      'postgres-2026-01-01T00-00-60-000Z-444444444444.dump.enc',
    ];
    for (const name of valid) {
      writeFileSync(path.join(temp, name), 'encrypted', { mode: 0o600 });
      writeFileSync(path.join(temp, `${name}.manifest.json`), '{}', { mode: 0o600 });
    }
    writeFileSync(path.join(temp, productionLegacy), 'legacy-encrypted', { mode: 0o600 });
    writeFileSync(path.join(temp, `${productionLegacy}.manifest.json`), 'not-json', { mode: 0o600 });
    writeFileSync(path.join(temp, manifestlessLegacy), 'legacy-without-manifest', { mode: 0o600 });
    writeFileSync(path.join(temp, unknownManifest), 'unknown-manifest-data', { mode: 0o600 });
    for (const name of impossibleFinals) {
      writeFileSync(path.join(temp, name), `impossible:${name}`, { mode: 0o600 });
      if (name.includes('-111111111111.') || name.endsWith('Z.dump.enc')) {
        writeFileSync(path.join(temp, `${name}.manifest.json`), `impossible-manifest:${name}`, { mode: 0o600 });
      }
    }
    const currentOrphans = Array.from({ length: 10 }, (_, index) => (
      `postgres-2099-12-${String(index + 1).padStart(2, '0')}T00-00-00-000Z-${String(index).padStart(12, '0')}.dump.enc`
    ));
    const partialCollision = '.postgres-stale.dump.enc.partial-artifact-deadbeef';
    const orphanManifest = 'postgres-2099-12-31T00-00-00-000Z-cccccccccccc.dump.enc.manifest.json';
    for (const name of currentOrphans) {
      writeFileSync(path.join(temp, name), 'orphan', { mode: 0o600 });
    }
    writeFileSync(path.join(temp, partialCollision), 'partial', { mode: 0o600 });
    writeFileSync(path.join(temp, orphanManifest), '{}', { mode: 0o600 });
    const validRecords = valid.map((name) => backupIdentityRecord(temp, name));
    try {
      const result = runBash(`
        source "$1"
        BACKUP_DIR="$BACKUP_DIR_FIXTURE"
        cleanup_backup_orphans
        list_valid_backup_artifacts() { printf '%s\n' "$VALID_RECORDS"; }
        prune_backups
      `, { BACKUP_DIR_FIXTURE: temp, VALID_RECORDS: validRecords.join('\n') });
      assert.equal(result.status, 0, result.stderr);
      const impossibleManifests = impossibleFinals
        .filter((name) => name.includes('-111111111111.') || name.endsWith('Z.dump.enc'))
        .map((name) => `${name}.manifest.json`);
      const preserved = [
        ...valid.flatMap((name) => [name, `${name}.manifest.json`]),
        productionLegacy,
        `${productionLegacy}.manifest.json`,
        manifestlessLegacy,
        unknownManifest,
        ...impossibleFinals,
        ...impossibleManifests,
        ...currentOrphans,
        partialCollision,
        orphanManifest,
      ];
      assert.deepEqual(readdirSync(temp).sort(), preserved.sort());
      assert.equal(readFileSync(path.join(temp, productionLegacy), 'utf8'), 'legacy-encrypted');
      assert.equal(readFileSync(path.join(temp, `${productionLegacy}.manifest.json`), 'utf8'), 'not-json');
      assert.equal(readFileSync(path.join(temp, manifestlessLegacy), 'utf8'), 'legacy-without-manifest');
      assert.equal(readFileSync(path.join(temp, unknownManifest), 'utf8'), 'unknown-manifest-data');
      for (const name of impossibleFinals) {
        assert.equal(readFileSync(path.join(temp, name), 'utf8'), `impossible:${name}`);
      }

      const malformed = 'manual.dump.enc';
      writeFileSync(path.join(temp, malformed), 'encrypted', { mode: 0o600 });
      writeFileSync(path.join(temp, `${malformed}.manifest.json`), '{}', { mode: 0o600 });
      const malformedRecord = backupIdentityRecord(temp, malformed);
      const rejected = runBash(`
        source "$1"
        BACKUP_DIR="$BACKUP_DIR_FIXTURE"
        cleanup_backup_orphans
        list_valid_backup_artifacts() { printf '%s\n' "$MALFORMED_RECORD"; }
        set +e
        prune_backups
        rc=$?
        set -e
        printf '%s' "$rc"
      `, { BACKUP_DIR_FIXTURE: temp, MALFORMED_RECORD: malformedRecord });
      assert.equal(rejected.status, 0, rejected.stderr);
      assert.match(rejected.stdout, /^[1-9][0-9]*$/);
      assert.match(rejected.stderr, /unsafe identity record/);
      assert.equal(existsSync(path.join(temp, malformed)), true);
      assert.equal(existsSync(path.join(temp, `${malformed}.manifest.json`)), true);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('inventory validates and emits only current names while ignoring exact legacy names', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-backup-inventory-'));
    chmodSync(temp, 0o700);
    const current = 'postgres-2026-08-31T12-00-00-000Z-abcdef123456.dump.enc';
    const productionLegacy = 'postgres-2026-08-30T16-47-04-492Z.dump.enc';
    const manifestlessLegacy = 'postgres-2026-08-29T16-47-04-492Z.dump.enc';
    const unknownManifest = 'operator-copy.dump.enc.manifest.json';
    writeInventoryBackupPair(temp, current);
    writeFileSync(path.join(temp, productionLegacy), 'legacy-encrypted', { mode: 0o600 });
    writeFileSync(path.join(temp, `${productionLegacy}.manifest.json`), 'not-json', { mode: 0o600 });
    writeFileSync(path.join(temp, manifestlessLegacy), 'legacy-without-manifest', { mode: 0o600 });
    writeFileSync(path.join(temp, unknownManifest), 'unknown-manifest-data', { mode: 0o600 });
    try {
      const accepted = runLocalBackupInventory(temp, `
        cleanup_backup_orphans
        inventory=$(list_valid_backup_artifacts)
        prune_backups
        printf '%s' "$inventory"
      `);
      assert.equal(accepted.status, 0, accepted.stderr);
      const acceptedFields = accepted.stdout.split('\t');
      assert.equal(acceptedFields.length, 19);
      assert.equal(acceptedFields[0], current);
      assert.ok(acceptedFields.slice(1).every((field) => /^-?[0-9]+$/.test(field)));
      for (const preserved of [
        productionLegacy,
        `${productionLegacy}.manifest.json`,
        manifestlessLegacy,
        unknownManifest,
      ]) assert.equal(existsSync(path.join(temp, preserved)), true, preserved);

      const unknownArtifact = 'zz-operator-copy.dump.enc';
      writeFileSync(path.join(temp, unknownArtifact), 'unknown-artifact', { mode: 0o600 });
      const unknownRejected = runLocalBackupInventory(temp, 'cleanup_backup_orphans; list_valid_backup_artifacts');
      assert.notEqual(unknownRejected.status, 0);
      assert.equal(unknownRejected.stdout, '', 'failed inventory must not emit a partial current-name list');
      assert.match(unknownRejected.stderr, /unsafe backup artifact name/);
      assert.equal(existsSync(path.join(temp, unknownArtifact)), true);
      rmSync(path.join(temp, unknownArtifact));

      const hostileArtifact = 'postgres-2099-01-01T00-00-00-000Z-abc\ndef123456.dump.enc';
      writeFileSync(path.join(temp, hostileArtifact), 'hostile-artifact', { mode: 0o600 });
      const hostileRejected = runLocalBackupInventory(temp, 'cleanup_backup_orphans; list_valid_backup_artifacts');
      assert.notEqual(hostileRejected.status, 0);
      assert.equal(hostileRejected.stdout, '');
      assert.match(hostileRejected.stderr, /unsafe backup artifact name/);
      assert.match(hostileRejected.stderr, /\\n/);
      assert.equal(existsSync(path.join(temp, hostileArtifact)), true);
      rmSync(path.join(temp, hostileArtifact));

      const impossibleArtifacts = [
        'postgres-2026-13-01T00-00-00-000Z-111111111111.dump.enc',
        'postgres-2026-04-31T00-00-00-000Z-222222222222.dump.enc',
        'postgres-2025-02-29T00-00-00-000Z.dump.enc',
        'postgres-2026-01-01T24-00-00-000Z-333333333333.dump.enc',
        'postgres-2026-01-01T00-60-00-000Z.dump.enc',
        'postgres-2026-01-01T00-00-60-000Z-444444444444.dump.enc',
      ];
      for (const impossibleArtifact of impossibleArtifacts) {
        const impossiblePath = path.join(temp, impossibleArtifact);
        writeFileSync(impossiblePath, `preserve:${impossibleArtifact}`, { mode: 0o600 });
        const impossibleRejected = runLocalBackupInventory(
          temp,
          'cleanup_backup_orphans; list_valid_backup_artifacts',
        );
        assert.notEqual(impossibleRejected.status, 0, impossibleArtifact);
        assert.equal(impossibleRejected.stdout, '');
        assert.match(impossibleRejected.stderr, /unsafe backup artifact name/);
        assert.equal(readFileSync(impossiblePath, 'utf8'), `preserve:${impossibleArtifact}`);
        rmSync(impossiblePath);
      }

      const invalidCurrent = 'postgres-2099-01-02T00-00-00-000Z-deadbeefcafe.dump.enc';
      writeInventoryBackupPair(temp, invalidCurrent, { sha256: '0'.repeat(64) });
      const invalidRejected = runLocalBackupInventory(temp, 'cleanup_backup_orphans; prune_backups');
      assert.notEqual(invalidRejected.status, 0);
      assert.equal(invalidRejected.stdout, '');
      assert.match(invalidRejected.stderr, /backup encrypted digest mismatch/);
      assert.equal(existsSync(path.join(temp, invalidCurrent)), true);
      assert.equal(existsSync(path.join(temp, `${invalidCurrent}.manifest.json`)), true);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('keeps only the newest ten current pairs and rejects validation-to-prune drift', () => {
    const names = Array.from({ length: 11 }, (_, index) => (
      `postgres-2026-06-${String(index + 1).padStart(2, '0')}T00-00-00-000Z-${String(index).padStart(12, '0')}.dump.enc`
    ));

    const retained = mkdtempSync(path.join(tmpdir(), 'astranull-identity-retention-'));
    chmodSync(retained, 0o700);
    try {
      for (const name of names) writeInventoryBackupPair(retained, name);
      const pruned = runLocalBackupInventory(retained, 'cleanup_backup_orphans; prune_backups');
      assert.equal(pruned.status, 0, pruned.stderr);
      assert.equal(existsSync(path.join(retained, names[0])), false);
      assert.equal(existsSync(path.join(retained, `${names[0]}.manifest.json`)), false);
      for (const name of names.slice(1)) {
        assert.equal(existsSync(path.join(retained, name)), true, name);
        assert.equal(existsSync(path.join(retained, `${name}.manifest.json`)), true, `${name} manifest`);
      }
      const quarantines = readdirSync(retained)
        .filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
      assert.equal(quarantines.length, 1);
      assert.equal(readdirSync(retained).length, 21);
      assert.deepEqual(readdirSync(path.join(retained, quarantines[0])).sort(), ['artifact', 'manifest']);
      assert.equal(statSync(path.join(retained, quarantines[0], 'artifact')).size, 0);
      assert.equal(statSync(path.join(retained, quarantines[0], 'manifest')).size, 0);
    } finally {
      rmSync(retained, { recursive: true, force: true });
    }

    const drifted = mkdtempSync(path.join(tmpdir(), 'astranull-identity-drift-'));
    chmodSync(drifted, 0o700);
    try {
      for (const name of names) writeInventoryBackupPair(drifted, name);
      const boundary = runLocalBackupInventory(drifted, `
        records=$(list_valid_backup_artifacts)
        chmod 640 "$DRIFT_MANIFEST"
        list_valid_backup_artifacts() { printf '%s\n' "$records"; }
        set +e
        prune_backups
        rc=$?
        set -e
        printf '%s' "$rc"
      `, { DRIFT_MANIFEST: path.join(drifted, `${names[0]}.manifest.json`) });
      assert.equal(boundary.status, 0, boundary.stderr);
      assert.match(boundary.stdout, /^[1-9][0-9]*$/);
      assert.match(boundary.stderr, /identity changed/);
      assert.equal(readdirSync(drifted).length, 22);
      for (const name of names) {
        assert.equal(existsSync(path.join(drifted, name)), true, name);
        assert.equal(existsSync(path.join(drifted, `${name}.manifest.json`)), true, `${name} manifest`);
      }
    } finally {
      rmSync(drifted, { recursive: true, force: true });
    }
  });

  it('uses the exact transferred retention helper before checkout when the host ROOT lacks it', () => {
    const names = Array.from({ length: 11 }, (_, index) => (
      `postgres-2026-07-${String(index + 1).padStart(2, '0')}T00-00-00-000Z-${String(index).padStart(12, '0')}.dump.enc`
    ));
    const oldRoot = mkdtempSync(path.join(tmpdir(), 'astranull-old-aws-root-'));
    const backupDir = mkdtempSync(path.join(tmpdir(), 'astranull-transferred-helper-backups-'));
    const deploySha = 'a'.repeat(40);
    const remoteHelper = `/tmp/astranull-postgres-retention-helper-${deploySha}-${process.pid}-${Date.now()}.py`;
    chmodSync(oldRoot, 0o700);
    chmodSync(backupDir, 0o700);
    writeFileSync(remoteHelper, readFileSync(path.join(ROOT, 'scripts/postgres-retention-helper.py')), { mode: 0o600 });
    chmodSync(remoteHelper, 0o600);
    try {
      for (const name of names) writeInventoryBackupPair(backupDir, name);
      const records = names.map((name) => backupIdentityRecord(backupDir, name));
      const result = runLocalBackupInventory(backupDir, `
        ROOT="$OLD_ROOT_FIXTURE"
        SHA="$DEPLOY_SHA_FIXTURE"
        ASTRANULL_DEPLOY_POSTGRES_RETENTION_HELPER="$TRANSFERRED_HELPER_FIXTURE"
        export ASTRANULL_DEPLOY_POSTGRES_RETENTION_HELPER
        [[ ! -e "$ROOT/scripts/postgres-retention-helper.py" ]]
        list_valid_backup_artifacts() { printf '%s\n' "$VALID_RECORDS"; }
        prune_backups
      `, {
        OLD_ROOT_FIXTURE: oldRoot,
        DEPLOY_SHA_FIXTURE: deploySha,
        TRANSFERRED_HELPER_FIXTURE: remoteHelper,
        VALID_RECORDS: records.join('\n'),
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(existsSync(path.join(backupDir, names[0])), false);
      assert.equal(existsSync(path.join(backupDir, `${names[0]}.manifest.json`)), false);
      assert.equal(existsSync(remoteHelper), true, 'deploy helper must not remove the workflow-owned transfer');
      const quarantines = readdirSync(backupDir)
        .filter((entry) => entry.startsWith('.postgres-retention-quarantine-'));
      assert.equal(quarantines.length, 1);
      assert.equal(statSync(path.join(backupDir, quarantines[0], 'artifact')).size, 0);
      assert.equal(statSync(path.join(backupDir, quarantines[0], 'manifest')).size, 0);
    } finally {
      rmSync(remoteHelper, { force: true });
      rmSync(oldRoot, { recursive: true, force: true });
      rmSync(backupDir, { recursive: true, force: true });
    }
  });

  it('counts ignored legacy artifacts toward the bounded 64-item inventory cap', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-legacy-backup-cap-'));
    chmodSync(temp, 0o700);
    const legacyName = (index) => `postgres-2026-08-30T16-47-04-${String(index).padStart(3, '0')}Z.dump.enc`;
    try {
      for (let index = 0; index < 64; index += 1) {
        writeFileSync(path.join(temp, legacyName(index)), `legacy-${index}`, { mode: 0o600 });
      }
      const atCap = runLocalBackupInventory(temp, 'cleanup_backup_orphans; prune_backups');
      assert.equal(atCap.status, 0, atCap.stderr);
      assert.equal(atCap.stdout, '');
      assert.equal(readdirSync(temp).length, 64);

      writeFileSync(path.join(temp, legacyName(64)), 'legacy-64', { mode: 0o600 });
      const overCap = runLocalBackupInventory(temp, 'cleanup_backup_orphans; prune_backups');
      assert.notEqual(overCap.status, 0);
      assert.equal(overCap.stdout, '');
      assert.match(overCap.stderr, /backup inventory exceeds bounded maximum 64/);
      assert.equal(readdirSync(temp).length, 65);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('prunes only obsolete exact-SHA AstraNull tags and preserves bundle/running references', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-image-prune-'));
    const stateDir = path.join(temp, 'state');
    const refs = path.join(temp, 'refs');
    const calls = path.join(temp, 'calls');
    const currentTags = ['1', '2', '3', '4'].map((char) => char.repeat(40));
    const pendingTags = ['5', '6', '7', '8'].map((char) => char.repeat(40));
    const runningTag = '9'.repeat(40);
    const obsoleteTags = ['a'.repeat(40), 'b'.repeat(40)];
    const idFor = (tag) => `sha256:${tag[0].repeat(64)}`;
    mkdirSync(stateDir, { mode: 0o700 });
    writeFileSync(refs, [
      ...currentTags, ...pendingTags, runningTag,
    ].map((tag) => `astranull-control-plane:${tag}|${idFor(tag)}`).concat([
      `astranull-control-plane:${obsoleteTags[0]}|${idFor(obsoleteTags[0])}`,
      `astranull-release-validator:${obsoleteTags[1]}|${idFor(obsoleteTags[1])}`,
      `ubuntu:latest|sha256:${'f'.repeat(64)}`,
    ]).join('\n') + '\n');
    try {
      const result = runBash(`
        source "$1"
        DEPLOY_STATE_DIR="$STATE_DIR"
        CURRENT_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-current"
        PENDING_RELEASE_BUNDLE_FILE="$STATE_DIR/release-image-pending"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
        RELEASE_VALIDATOR_IMAGE_STATE_FILE="$STATE_DIR/release-validator-image-state"
        write_release_bundle_atomic "$CURRENT_RELEASE_BUNDLE_FILE" "$C1" "$C1_ID" "$C2" "$C2_ID" "$C3" "$C3_ID" 1 "$C4" "$C4_ID"
        write_pending_release_bundle "$P1" "$P1_ID" "$P2" "$P2_ID" "$P3" "$P3_ID" 1 "$P4" "$P4_ID"
        docker() {
          if [[ "$1 $2 $3" == 'container ls -q' ]]; then printf running-cid; return; fi
          if [[ "$1 $2" == 'inspect --format' ]]; then printf 'astranull-control-plane:%s' "$RUNNING_TAG"; return; fi
          if [[ "$1 $2" == 'image ls' ]]; then cut -d'|' -f1 "$REFS"; return; fi
          if [[ "$1 $2 $3" == 'image inspect --format' && "$4" == '{{.Id}}' ]]; then
            awk -F'|' -v ref="$5" '$1 == ref { print $2; found=1 } END { exit !found }' "$REFS"; return
          fi
          if [[ "$1 $2" == 'image rm' && "$3" =~ ^astranull-(control-plane|release-validator): ]]; then
            printf 'rm-tag|%s\n' "$3" >> "$CALLS"
            awk -F'|' -v ref="$3" '$1 != ref' "$REFS" > "$REFS.next" && mv "$REFS.next" "$REFS"
            return
          fi
          if [[ "$1 $2" == 'image inspect' && "$3" =~ ^astranull-(control-plane|release-validator): ]]; then
            grep -Fq "$3|" "$REFS"; return
          fi
          if [[ "$1 $2 $3" == 'image inspect --format' && "$4" == '{{json .RepoTags}}' ]]; then
            if grep -Fq "|$5" "$REFS"; then printf '["tag"]'; else printf null; fi
            return
          fi
          if [[ "$1 $2" == 'image rm' && "$3" == sha256:* ]]; then printf 'rm-id|%s\n' "$3" >> "$CALLS"; return; fi
          return 97
        }
        timeout() { if [[ "$1" == -k ]]; then shift 3; fi; "$@"; }
        bounded_prune_release_images
      `, {
        CALLS: calls,
        C1: currentTags[0], C1_ID: idFor(currentTags[0]),
        C2: currentTags[1], C2_ID: idFor(currentTags[1]),
        C3: currentTags[2], C3_ID: idFor(currentTags[2]),
        C4: currentTags[3], C4_ID: idFor(currentTags[3]),
        P1: pendingTags[0], P1_ID: idFor(pendingTags[0]),
        P2: pendingTags[1], P2_ID: idFor(pendingTags[1]),
        P3: pendingTags[2], P3_ID: idFor(pendingTags[2]),
        P4: pendingTags[3], P4_ID: idFor(pendingTags[3]),
        REFS: refs,
        RUNNING_TAG: runningTag,
        STATE_DIR: stateDir,
      });
      assert.equal(result.status, 0, result.stderr);
      const remaining = readFileSync(refs, 'utf8');
      for (const tag of [...currentTags, ...pendingTags, runningTag]) assert.match(remaining, new RegExp(tag));
      for (const tag of obsoleteTags) assert.doesNotMatch(remaining, new RegExp(tag));
      assert.match(remaining, /ubuntu:latest/);
      const log = readFileSync(calls, 'utf8');
      assert.match(log, new RegExp(`rm-tag\\|astranull-control-plane:${obsoleteTags[0]}`));
      assert.match(log, new RegExp(`rm-tag\\|astranull-release-validator:${obsoleteTags[1]}`));
      assert.doesNotMatch(log, /ubuntu/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rejects same-tag different-ID collisions in deploy and restore', () => {
    const tag = '9'.repeat(40);
    const leftId = `sha256:${'1'.repeat(64)}`;
    const rightId = `sha256:${'2'.repeat(64)}`;
    for (const script of [DEPLOY, RESTORE]) {
      const rejected = runBash(`
        source "$1"
        assert_image_identities_compatible left "$TAG" "$LEFT_ID" right "$TAG" "$RIGHT_ID"
      `, { LEFT_ID: leftId, RIGHT_ID: rightId, TAG: tag }, script);
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, /assign tag .* to different image IDs/);

      const accepted = runBash(`
        source "$1"
        assert_image_identities_compatible left "$TAG" "$LEFT_ID" right "$TAG" "$LEFT_ID"
      `, { LEFT_ID: leftId, TAG: tag }, script);
      assert.equal(accepted.status, 0, accepted.stderr);
    }
  });
});

describe('AWS restore image identity', () => {
  it('validates Compose with the persisted exact image runner, never host node', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-node-'));
    const imageId = `sha256:${'8'.repeat(64)}`;
    const composeJson = '{"services":{"control-plane":{}}}';
    const { dockerLog, hostNodeLog } = writeFakeContainerNodeRunner(temp);
    try {
      const result = runBash(`
        source "$1"
        release_validator_image_id="$EXPECTED_IMAGE_ID"
        compose_timeout() {
          [[ "$*" == '30 --profile ops config --format json' ]] || return 88
          printf '%s' "$EXPECTED_COMPOSE_JSON"
        }
        validate_compose "$release_validator_image_id" connector_mode
        printf '%s\n' "$connector_mode"
      `, {
        EXPECTED_COMPOSE_JSON: composeJson,
        EXPECTED_IMAGE_ID: imageId,
        FAKE_DOCKER_LOG: dockerLog,
        HOST_NODE_LOG: hostNodeLog,
        EXPECTED_CONNECTOR_MODE: 'disabled',
        PATH: `${temp}:${process.env.PATH}`,
      }, RESTORE);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'disabled\n');
      assert.equal(
        readFileSync(dockerLog, 'utf8').trim(),
        `${imageId}|node|scripts/validate-aws-compose-secrets.mjs`,
      );
      assert.equal(existsSync(hostNodeLog), false);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('requires durable core/ops state instead of inferring workers from Git or tags', () => {
    const missing = path.join(tmpdir(), `astranull-missing-core-${process.pid}-${Date.now()}`);
    const result = runBash(`
      source "$1"
      CORE_WORKER_IMAGE_STATE_FILE="$MISSING"
      read_control_plane_image_tag() { printf '%s\\n' "${'1'.repeat(40)}"; }
      read_control_plane_image_id() { printf 'sha256:%s\\n' "${'a'.repeat(64)}"; }
      git() { exit 97; }
      rebind_control_plane_image_tag() { exit 98; }
      load_restore_image_identity
    `, { MISSING: missing }, RESTORE);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /required persisted core\/ops worker state is missing/);
  });

  it('loads and verifies independent persisted control-plane and core/ops identities', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-identity-'));
    const controlTag = 'd'.repeat(40);
    const coreTag = 'e'.repeat(40);
    const controlImageId = `sha256:${'3'.repeat(64)}`;
    const coreImageId = `sha256:${'4'.repeat(64)}`;
    const fakeDocker = path.join(temp, 'docker');
    writeFileSync(path.join(temp, 'control-plane-image-tag'), `${controlTag}\n${controlImageId}\n`, { mode: 0o600 });
    writeFileSync(path.join(temp, 'core-worker-image-state'), `${coreTag}\n${coreImageId}\n`, { mode: 0o600 });
    writeFakeTimeout(temp);
    writeFileSync(fakeDocker, `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'image inspect' ]]; then
  case "$5" in
    "$CONTROL_IMAGE_ID"|"astranull-control-plane:$CONTROL_TAG") printf '%s\\n' "$CONTROL_IMAGE_ID" ;;
    "$CORE_IMAGE_ID"|"astranull-control-plane:$CORE_TAG") printf '%s\\n' "$CORE_IMAGE_ID" ;;
    *) exit 81 ;;
  esac
elif [[ "$1 $2" == 'image tag' ]]; then
  [[ ( "$3" == "$CONTROL_IMAGE_ID" && "$4" == "astranull-control-plane:$CONTROL_TAG" ) \
    || ( "$3" == "$CORE_IMAGE_ID" && "$4" == "astranull-control-plane:$CORE_TAG" ) ]]
elif [[ "$1" == inspect && "$3" == '{{.Config.Image}}' ]]; then
  if [[ "$4" == control-cid ]]; then printf '%s\\n' "$CONTROL_IMAGE_ID";
  else printf '%s\\n' "$CORE_IMAGE_ID"; fi
elif [[ "$1" == inspect && "$3" == '{{.Image}}' ]]; then
  if [[ "$4" == control-cid ]]; then printf '%s\\n' "$CONTROL_IMAGE_ID";
  else printf '%s\\n' "$CORE_IMAGE_ID"; fi
else
  exit 82
fi
`);
    chmodSync(fakeDocker, 0o755);

    try {
      const result = runBash(`
        source "$1"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
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
        printf '%s|%s|%s|%s|%s' "$control_plane_tag" "$core_worker_tag" "$ASTRANULL_CONTROL_PLANE_IMAGE_TAG" "$ASTRANULL_WORKER_IMAGE_TAG" "$ASTRANULL_IMAGE_TAG"
      `, {
        CONTROL_IMAGE_ID: controlImageId,
        CONTROL_TAG: controlTag,
        CORE_IMAGE_ID: coreImageId,
        CORE_TAG: coreTag,
        PATH: `${temp}:${process.env.PATH}`,
        STATE_DIR: temp,
      }, RESTORE);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `${controlTag}|${coreTag}|${controlTag}|${coreTag}|${coreTag}`);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });


  it('loads enabled connector identity only after durable core state and validated Compose intent', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-connector-'));
    const controlTag = '1'.repeat(40);
    const coreTag = '2'.repeat(40);
    const connectorTag = '3'.repeat(40);
    const controlImageId = `sha256:${'a'.repeat(64)}`;
    const coreImageId = `sha256:${'b'.repeat(64)}`;
    const connectorImageId = `sha256:${'c'.repeat(64)}`;
    const calls = path.join(temp, 'calls.log');
    writeFileSync(path.join(temp, 'control-plane-image-tag'), `${controlTag}\n${controlImageId}\n`, { mode: 0o600 });
    writeFileSync(path.join(temp, 'core-worker-image-state'), `${coreTag}\n${coreImageId}\n`, { mode: 0o600 });
    writeFileSync(path.join(temp, 'connector-image-state'), `${connectorTag}\n${connectorImageId}\n`, { mode: 0o600 });
    try {
      const result = runBash(`
        source "$1"
        CONTROL_PLANE_IMAGE_TAG_FILE="$STATE_DIR/control-plane-image-tag"
        CORE_WORKER_IMAGE_STATE_FILE="$STATE_DIR/core-worker-image-state"
        CONNECTOR_IMAGE_STATE_FILE="$STATE_DIR/connector-image-state"
        rebind_control_plane_image_tag() { printf 'rebind-control\\n' >> "$CALLS"; }
        rebind_core_worker_image_tag() { printf 'rebind-core\\n' >> "$CALLS"; }
        rebind_connector_image_tag() { printf 'rebind-connector\\n' >> "$CALLS"; }
        connector_image_supports_split_mode() { printf 'compat-connector\\n' >> "$CALLS"; }
        verify_service_image_tag() { printf 'verify|%s|%s|%s\\n' "$1" "$2" "$3" >> "$CALLS"; }
        load_restore_image_identity
        connector_mode=enabled
        load_restore_connector_intent
        verify_restored_image_identity
        printf '%s|%s|%s|%s' "$connector_enabled" "$ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG" "$connector_tag" "$connector_image_id"
      `, { CALLS: calls, STATE_DIR: temp }, RESTORE);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `1|${connectorTag}|${connectorTag}|${connectorImageId}`);
      const log = readFileSync(calls, 'utf8');
      assert.match(log, /rebind-control[\s\S]*rebind-core[\s\S]*rebind-connector/);
      assert.match(log, /compat-connector/);
      assert.match(log, new RegExp(`verify\\|probe-worker\\|${coreTag}\\|${coreImageId}`));
      assert.match(log, new RegExp(`verify\\|connector-poll-scheduler\\|${connectorTag}\\|${connectorImageId}`));
      assert.match(log, new RegExp(`verify\\|connector-poll-runner\\|${connectorTag}\\|${connectorImageId}`));
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('makes validated Compose intent authoritative for restore connectors', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-connector-intent-'));
    const staleState = path.join(temp, 'connector-image-state');
    writeFileSync(staleState, 'stale-state-that-must-not-be-read\n', { mode: 0o600 });
    try {
      const disabled = runBash(`
        source "$1"
        CONNECTOR_IMAGE_STATE_FILE="$STALE_STATE"
        control_plane_image_id="sha256:${'a'.repeat(64)}"
        core_worker_tag="${'4'.repeat(40)}"
        core_worker_image_id="sha256:${'b'.repeat(64)}"
        connector_mode=disabled
        rebind_connector_image_tag() { exit 91; }
        present=1
        stop_remove_services() { present=0; }
        compose_timeout() {
          case "$*" in
            '30 ps --all -q connector-poll-scheduler'|'30 ps --all -q connector-poll-runner')
              if ((present)); then printf stale-cid; fi
              return 0
              ;;
            '300 up -d --wait --wait-timeout 240 postgres control-plane probe-worker password-recovery-worker test-policy-runner caddy') return 0 ;;
            *) return 92 ;;
          esac
        }
        load_restore_connector_intent
        start_core_stack
        verify_services_absent connector-poll-scheduler connector-poll-runner
        printf '%s|%s|%s' "$connector_mode" "$connector_enabled" "$ASTRANULL_CONNECTOR_WORKER_IMAGE_TAG"
      `, { STALE_STATE: staleState }, RESTORE);
      assert.equal(disabled.status, 0, disabled.stderr);
      assert.equal(disabled.stdout, `disabled|0|${'4'.repeat(40)}`);
      assert.equal(readFileSync(staleState, 'utf8'), 'stale-state-that-must-not-be-read\n');

      const enabledWithoutState = runBash(`
        source "$1"
        CONNECTOR_IMAGE_STATE_FILE="$MISSING_STATE"
        control_plane_tag="${'1'.repeat(40)}"
        control_plane_image_id="sha256:${'a'.repeat(64)}"
        core_worker_tag="${'2'.repeat(40)}"
        core_worker_image_id="sha256:${'b'.repeat(64)}"
        connector_mode=enabled
        load_restore_connector_intent
      `, { MISSING_STATE: path.join(temp, 'missing-connector-state') }, RESTORE);
      assert.notEqual(enabledWithoutState.status, 0);
      assert.match(enabledWithoutState.stderr, /connectors are enabled but persisted connector state is missing/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('repairs stopped same-tag control and core identities from persisted IDs', () => {
    const temp = mkdtempSync(path.join(tmpdir(), 'astranull-restore-stopped-'));
    const sameTag = '9'.repeat(40);
    const expectedImageId = `sha256:${'c'.repeat(64)}`;
    const clobberedImageId = `sha256:${'d'.repeat(64)}`;
    const stateFile = path.join(temp, 'control-plane-image-tag');
    const coreStateFile = path.join(temp, 'core-worker-image-state');
    const tagFile = path.join(temp, 'tag-image-id');
    const callLog = path.join(temp, 'docker.log');
    const fakeDocker = path.join(temp, 'docker');
    writeFileSync(stateFile, `${sameTag}\n${expectedImageId}\n`, { mode: 0o600 });
    writeFileSync(coreStateFile, `${sameTag}\n${expectedImageId}\n`, { mode: 0o600 });
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
        CORE_WORKER_IMAGE_STATE_FILE="$CORE_STATE_FILE"
        compose_timeout() { [[ "$*" == '30 ps -q control-plane' ]]; }
        load_restore_image_identity
        verify_running_control_plane_state
        printf '%s|%s' "$control_plane_image_id" "$core_worker_image_id"
      `, {
        EXPECTED_IMAGE_ID: expectedImageId,
        CORE_STATE_FILE: coreStateFile,
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
    const coreStateFile = path.join(temp, 'core-worker-image-state');
    const fakeDocker = path.join(temp, 'docker');
    const callLog = path.join(temp, 'docker.log');
    writeFileSync(stateFile, `${tag}\n${expectedImageId}\n`, { mode: 0o600 });
    writeFileSync(coreStateFile, `${tag}\n${expectedImageId}\n`, { mode: 0o600 });
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
        CORE_WORKER_IMAGE_STATE_FILE="$CORE_STATE_FILE"
        load_restore_image_identity
      `, {
        EXPECTED_IMAGE_ID: expectedImageId,
        CORE_STATE_FILE: coreStateFile,
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

  it('makes restore EXIT cleanup claims depend on verified shutdown after the outage boundary', () => {
    const verified = runBash(`
      source "$1"
      succeeded=0
      outage_started=1
      plain_host=''
      cleanup_active_operation_containers_checked() { :; }
      cleanup_compose_render_checked() { :; }
      cleanup_compose_snapshot_checked() { :; }
      cleanup_env_snapshot_checked() { :; }
      stop_remove_services() { return 0; }
      cleanup
    `, {}, RESTORE);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stderr, /stopped, removed, and verified absent/);

    const survivor = runBash(`
      source "$1"
      succeeded=0
      outage_started=1
      plain_host=''
      cleanup_active_operation_containers_checked() { :; }
      cleanup_compose_render_checked() { :; }
      cleanup_compose_snapshot_checked() { :; }
      cleanup_env_snapshot_checked() { :; }
      stop_remove_services() { return 1; }
      cleanup
    `, {}, RESTORE);
    assert.notEqual(survivor.status, 0);
    assert.match(survivor.stderr, /shutdown could not be verified/);
    assert.doesNotMatch(survivor.stderr, /verified absent/);

    const preflight = runBash(`
      source "$1"
      succeeded=0
      outage_started=0
      plain_host=''
      cleanup_active_operation_containers_checked() { :; }
      cleanup_compose_render_checked() { :; }
      cleanup_compose_snapshot_checked() { :; }
      cleanup_env_snapshot_checked() { :; }
      stop_remove_services() { exit 99; }
      cleanup
    `, {}, RESTORE);
    assert.equal(preflight.status, 0, preflight.stderr);
    assert.match(preflight.stderr, /preflight failed before outage/);
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
      assert.match(result.stderr, /control-plane Config\.Image .* does not equal exact release ID/);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});
