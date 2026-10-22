import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPT = path.join(ROOT, 'ops/aws/configure-assistant.sh');
const WORKFLOW = readFileSync(path.join(ROOT, '.github/workflows/configure-assistant.yml'), 'utf8');
const TOKEN = 'runner-token-synthetic-0123456789abcdef';
const LLM_KEY = 'sk-test-synthetic-key-0123456789';
const HEADERS = '{"User-Agent":"astranull-assistant-runner/1.0","x-opencode-session":"astranull-production"}';
const BASE_URL = 'https://opencode.ai/zen/go/v1';
const CONTROL_ID = `sha256:${'a'.repeat(64)}`;
const CORE_ID = `sha256:${'b'.repeat(64)}`;

const STUB_LIB = String.raw`
ROOT=$STUB_ROOT
ENV_FILE=$ROOT/ops/aws/.env
COMPOSE_REPO_PATH=ops/aws/docker-compose.yml
CURRENT_RELEASE_BUNDLE_FILE=$ROOT/bundle
COMPOSE_RENDER_OWNED=0
ENV_SNAPSHOT=''
log() { printf '%s\n' "$*" >> "$STUB_LOG"; }
acquire_deploy_lock() { log lock; }
validate_env_source() { log validate-env; }
snapshot_env_file() { ENV_SNAPSHOT=$ROOT/snapshot; cp "$ENV_FILE" "$ENV_SNAPSHOT"; log snapshot; }
cleanup_compose_snapshots() { rm -f -- "$ENV_SNAPSHOT"; ENV_SNAPSHOT=''; log cleanup; }
release_bundle_load() {
  release_bundle_control_tag=$(git rev-parse HEAD)
  release_bundle_control_image_id=$STUB_CONTROL_ID
  release_bundle_core_tag=$release_bundle_control_tag
  release_bundle_core_image_id=$STUB_CORE_ID
  release_bundle_connector_enabled=0
  release_bundle_connector_image_id=''
}
release_runtime_service_matches_id() { log "match $1 $2"; [[ $@{STUB_MISMATCH:-0} != 1 ]]; }
compose_timeout() {
  log "compose $*"
  log "images $@{ASTRANULL_CONTROL_PLANE_IMAGE_ID:-} $@{ASTRANULL_CORE_WORKER_IMAGE_ID:-} $@{ASTRANULL_CONNECTOR_WORKER_IMAGE_ID:-}"
  log "snapshot-has-base-url=$(grep -c '^ASTRANULL_ASSISTANT_LLM_BASE_URL=' "$ENV_SNAPSHOT")"
  [[ $@{STUB_COMPOSE_FAIL:-0} != 1 ]]
}
verify_service_image_tag() { log "verify $1 $2 $3"; }
check_control_plane() { log check-control-plane; }
check_service_health() { log "health $1"; }
`.replaceAll('$@{', '${');

const FAKE_STAT = `#!/usr/bin/env bash
case "$2" in
  %u) exec /usr/bin/stat -f %u "$4" ;;
  %a) exec /usr/bin/stat -f %Lp "$4" ;;
  *) exit 2 ;;
esac
`;

describe('configure-assistant.sh', () => {
  let work;
  let sha;
  let created = [];

  before(() => {
    work = mkdtempSync(path.join(tmpdir(), 'astranull-configure-assistant-'));
    const repo = path.join(work, 'repo');
    mkdirSync(path.join(repo, 'ops/aws'), { recursive: true });
    const git = (...args) => spawnSync('git', ['-C', repo, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
    git('init', '-q');
    writeFileSync(path.join(repo, 'file'), 'x');
    git('add', '.');
    git('commit', '-q', '-m', 'init');
    sha = git('rev-parse', 'HEAD').stdout.trim();
    mkdirSync(path.join(work, 'bin'));
    writeFileSync(path.join(work, 'bin/stat'), FAKE_STAT, { mode: 0o755 });
  });
  after(() => {
    for (const file of created) rmSync(file, { force: true });
    rmSync(work, { recursive: true, force: true });
  });

  const run = (args = {}, { stdin = `${TOKEN}\n${LLM_KEY}\n`, env = {} } = {}) => {
    const suffix = `${process.pid}${created.length + 1}`;
    const deployLib = `/tmp/astranull-deploy-${sha}-${suffix}-1.sh`;
    const stateLib = `/tmp/astranull-release-state-${sha}-${suffix}-1.sh`;
    writeFileSync(deployLib, STUB_LIB);
    writeFileSync(stateLib, '');
    created.push(deployLib, stateLib);
    const repo = path.join(work, 'repo');
    const envFile = path.join(repo, 'ops/aws/.env');
    writeFileSync(envFile, 'POSTGRES_PASSWORD=synthetic-db\nASTRANULL_ASSISTANT_ENABLED=0\nASTRANULL_ASSISTANT_RUNNER_TOKEN=old-token\nASTRANULL_ASSISTANT_LLM_API_KEY=old-key\nASTRANULL_PUBLIC_BASE_URL=https://example.test\n', { mode: 0o600 });
    chmodSync(envFile, 0o640);
    const log = path.join(work, `log-${suffix}`);
    const value = { enabled: '1', tenants: '*', model: 'deepseek-v4-flash', backend: 'openai', baseUrl: BASE_URL, llmModel: 'deepseek-v4-flash', headers: HEADERS, ...args };
    const result = spawnSync('bash', [SCRIPT, args.sha ?? sha, deployLib, stateLib, value.enabled, value.tenants, value.model, value.backend, value.baseUrl, value.llmModel, value.headers], {
      input: stdin,
      encoding: 'utf8',
      timeout: 20000,
      env: { PATH: `${path.join(work, 'bin')}:${process.env.PATH}`, STUB_ROOT: repo, STUB_LOG: log, STUB_CONTROL_ID: CONTROL_ID, STUB_CORE_ID: CORE_ID, HOME: work, ...env },
    });
    return { ...result, envFile, envText: readFileSync(envFile, 'utf8'), log: existsSync(log) ? readFileSync(log, 'utf8') : '' };
  };

  it('writes every assistant key and recreates only control-plane and assistant-runner on the deployed images', () => {
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.envText, /^POSTGRES_PASSWORD=synthetic-db$/m);
    assert.match(result.envText, /^ASTRANULL_PUBLIC_BASE_URL=https:\/\/example\.test$/m);
    assert.equal((result.envText.match(/^ASTRANULL_ASSISTANT_ENABLED=/gm) ?? []).length, 1);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_ENABLED=1$/m);
    assert.match(result.envText, new RegExp(`^ASTRANULL_ASSISTANT_RUNNER_TOKEN=${TOKEN}$`, 'm'));
    assert.match(result.envText, new RegExp(`^ASTRANULL_ASSISTANT_LLM_API_KEY=${LLM_KEY}$`, 'm'));
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_RUNNER_BACKEND=openai$/m);
    assert.match(result.envText, new RegExp(`^ASTRANULL_ASSISTANT_LLM_BASE_URL=${BASE_URL}$`, 'm'));
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_LLM_MODEL=deepseek-v4-flash$/m);
    assert.ok(result.envText.includes(`ASTRANULL_ASSISTANT_LLM_HEADERS='${HEADERS}'\n`));
    assert.doesNotMatch(result.envText, /old-token|old-key/);
    assert.equal(statSync(result.envFile).mode & 0o777, 0o640);
    const lines = result.log.trim().split('\n');
    const composeCalls = lines.filter((line) => line.startsWith('compose '));
    assert.deepEqual(composeCalls, ['compose 300 up -d --no-deps --force-recreate --wait --wait-timeout 240 control-plane assistant-runner']);
    assert.ok(lines.includes(`images ${CONTROL_ID} ${CORE_ID} ${CORE_ID}`));
    assert.ok(lines.includes('snapshot-has-base-url=1'));
    assert.ok(lines.includes(`match control-plane ${CONTROL_ID}`));
    assert.ok(lines.includes(`verify control-plane ${sha} ${CONTROL_ID}`));
    assert.ok(lines.includes(`verify assistant-runner ${sha} ${CORE_ID}`));
    assert.ok(lines.indexOf('check-control-plane') > lines.findIndex((line) => line.startsWith('compose ')));
    assert.ok(lines.includes('health assistant-runner'));
    assert.equal(lines.at(-1), 'cleanup');
    assert.match(result.stdout, /"status":"assistant_configured".*"recreated":\["control-plane","assistant-runner"\]/);
  });

  it('never prints or logs the runner token or the LLM API key', () => {
    const result = run();
    for (const text of [result.stdout, result.stderr, result.log]) {
      assert.ok(!text.includes(TOKEN) && !text.includes(LLM_KEY));
    }
  });

  it('blanks the secrets when the assistant is disabled and still recreates the two services', () => {
    const result = run({ enabled: '0' }, { stdin: `${TOKEN}\n${LLM_KEY}\n` });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_ENABLED=0$/m);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_RUNNER_TOKEN=$/m);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_LLM_API_KEY=$/m);
    assert.ok(!result.envText.includes(TOKEN) && !result.envText.includes(LLM_KEY));
  });

  it('does not keep an LLM key for the agy backend', () => {
    const result = run({ backend: 'agy', baseUrl: '', headers: '', llmModel: '' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_LLM_API_KEY=$/m);
    assert.match(result.envText, /^ASTRANULL_ASSISTANT_LLM_HEADERS=''$/m);
  });

  it('rejects invalid nonsecret inputs before the deploy library is sourced', () => {
    const cases = [
      { baseUrl: 'http://opencode.ai/zen/go/v1' },
      { baseUrl: 'https://evil.example.com/zen/go/v1' },
      { baseUrl: 'https://opencode.ai.evil.example.com/zen/go/v1' },
      { baseUrl: 'https://203.0.113.9/zen/go/v1' },
      { baseUrl: 'https://opencode.ai:8443/zen/go/v1' },
      { baseUrl: 'https://opencode.ai/zen/go/v1/' },
      { baseUrl: 'https://opencode.ai/other' },
      { baseUrl: 'HTTPS://OPENCODE.AI/zen/go/v1' },
      { baseUrl: 'https://user:pw@opencode.ai/v1' },
      { baseUrl: 'https://opencode.ai/v1?key=1' },
      { baseUrl: 'https://opencode.ai/v1#frag' },
      { baseUrl: 'https://opencode.ai/v1;rm' },
      { baseUrl: '' },
      { llmModel: 'bad model;rm' },
      { llmModel: 'a' },
      { headers: '{"Authorization":"x"}' },
      { headers: '{"Host":"x"}' },
      { headers: '{"X-A":"v","x-a":"w"}' },
      { headers: '{"bad name":"v"}' },
      { headers: '{"x-a":"$(id)"}' },
      { headers: '{"x-a":"it\'s"}' },
      { headers: '{"x-a":1}' },
      { headers: '["x"]' },
      { headers: '{"x-a":"v"' },
      { headers: `{${Array.from({ length: 9 }, (_, index) => `"x-h${index}":"v"`).join(',')}}` },
      { headers: `{"x-a":"${'a'.repeat(257)}"}` },
      { tenants: 'Bad Tenant' },
      { backend: 'other' },
      { enabled: '2' },
      { model: 'Bad;Model' },
    ];
    for (const args of cases) {
      const result = run(args);
      assert.notEqual(result.status, 0, JSON.stringify(args));
      assert.doesNotMatch(result.stderr, /transferred/, JSON.stringify(args));
      assert.match(result.stderr, /^assistant: /, JSON.stringify(args));
      assert.equal(result.log, '', `sourced the deploy library for ${JSON.stringify(args)}`);
      assert.doesNotMatch(result.envText, /LLM_BASE_URL/);
    }
  });

  it('rejects malformed secrets and a wrong release SHA before touching the environment file', () => {
    for (const stdin of ['short\nkey-0123456789abcdef\n', `${TOKEN}\n`, `${TOKEN}\nshort\n`, `${TOKEN}\nkey with space 0123456789\n`, '']) {
      const result = run({}, { stdin });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /^assistant: .*(runner token|API key)/, stdin);
      assert.equal(result.log, '');
      assert.doesNotMatch(result.envText, /LLM_BASE_URL/);
    }
    const wrongSha = run({ sha: 'f'.repeat(40) });
    assert.notEqual(wrongSha.status, 0);
    assert.equal(wrongSha.log, '');
  });

  it('refuses to change anything when the running control-plane does not match the canonical image', () => {
    const result = run({}, { env: { STUB_MISMATCH: '1' } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /does not uniquely match the canonical immutable image ID/);
    assert.doesNotMatch(result.envText, /LLM_BASE_URL/);
    assert.ok(!result.log.includes('compose '));
    assert.equal(result.log.trim().split('\n').at(-1), 'cleanup');
  });

  it('fails the run and still cleans the snapshot when the recreate fails', () => {
    const result = run({}, { env: { STUB_COMPOSE_FAIL: '1' } });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.log, /verify assistant-runner/);
    assert.equal(result.log.trim().split('\n').at(-1), 'cleanup');
    assert.ok(!result.stdout.includes('assistant_configured'));
  });

  it('keeps the script free of full redeploys, eval and secret argv', () => {
    const script = readFileSync(SCRIPT, 'utf8');
    assert.doesNotMatch(script, /\beval\b|main "|bash "\$DEPLOY_LIB_PATH"/);
    assert.match(script, /up -d --no-deps --force-recreate --wait --wait-timeout 240 control-plane assistant-runner/);
    assert.match(script, /IFS= read -r -t 30 RUNNER_TOKEN[\s\S]*IFS= read -r -t 30 LLM_API_KEY/);
    assert.doesNotMatch(script.split('\n').filter((line) => line.startsWith('#')).join('\n'), /--sha|password/i);
  });
});

describe('configure-assistant workflow', () => {
  it('passes the new settings only through env and sends both secrets on stdin', () => {
    assert.doesNotMatch(WORKFLOW, /llm_base_url/);
    assert.match(WORKFLOW, /llm_provider:[\s\S]*options: \['opencode-go'\]/);
    assert.match(WORKFLOW, /LLM_BASE_URL=https:\/\/opencode\.ai\/zen\/go\/v1/);
    assert.match(WORKFLOW, /"transfer-encoding"/);
    assert.match(WORKFLOW, /llm_headers:[\s\S]*default: '\{"User-Agent":"astranull-assistant-runner\/1\.0","x-opencode-session":"astranull-production"\}'/);
    assert.match(WORKFLOW, /LLM_API_KEY: \$\{\{ secrets\.ASTRANULL_ASSISTANT_LLM_API_KEY \}\}/);
    const runBlock = WORKFLOW.slice(WORKFLOW.indexOf('run: |'));
    assert.doesNotMatch(runBlock, /\$\{\{/);
    assert.match(runBlock, /printf '%s\\n%s\\n' "\$\{RUNNER_TOKEN:-\}" "\$\{LLM_API_KEY:-\}" \| timeout/);
    assert.doesNotMatch(runBlock, /bash '\$remote_deploy'/);
    assert.match(runBlock, /headers_pattern=/);
  });
});
