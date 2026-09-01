import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  ACCESSIBILITY_PASSWORD_RESET_CLIENT_KEY,
  ACCESSIBILITY_PASSWORD_RESET_EMAIL,
  ACCESSIBILITY_PASSWORD_RESET_ERROR_CODES,
  ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER,
  ACCESSIBILITY_PASSWORD_RESET_INVITE_TTL_MS,
  ACCESSIBILITY_PASSWORD_RESET_OPERATOR_CREATED_BY,
  ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
  createAccessibilityPasswordResetFailure,
  prepareAccessibilityPasswordResetEnvironment,
  readFramedAccessibilityPassword,
  resetAccessibilityRunnerPassword,
  resolveAccessibilityPasswordResetErrorCode,
} from '../../scripts/reset-accessibility-runner-password.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OPERATOR_PATH = path.join(ROOT, 'scripts/reset-accessibility-runner-password.mjs');
const WRAPPER_PATH = path.join(ROOT, 'ops/aws/reset-accessibility-runner-password.sh');
const WORKFLOW_PATH = path.join(ROOT, '.github/workflows/reset-accessibility-password.yml');
const CI_PATH = path.join(ROOT, '.github/workflows/ci.yml');

const OPERATOR_SOURCE = readFileSync(OPERATOR_PATH, 'utf8');
const WRAPPER_SOURCE = readFileSync(WRAPPER_PATH, 'utf8');
const WORKFLOW_SOURCE = readFileSync(WORKFLOW_PATH, 'utf8');
const CI_SOURCE = readFileSync(CI_PATH, 'utf8');

// A policy-passing fixture: 12+ chars, 4 character classes, and it does not contain the
// account email local part. It never leaves this test process.
const FIXTURE_PASSWORD = 'F1xture-Pw-9x-rotate';
const WEAK_PASSWORD = 'weak';
const FIXTURE_INVITE_TOKEN = 'invite-token-fixture-value';
const RUNNER_PASSWORD_ENV_KEY = 'ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD';
const AUTO_MIGRATE_ENV_KEY = 'ASTRANULL_POSTGRES_AUTO_MIGRATE';

function framedChunks(password, marker = ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER) {
  return [Buffer.from(`${password}\n${marker}\n`, 'utf8')];
}

function framedStream(password, options = {}) {
  return Readable.from(options.chunks ?? framedChunks(password, options.marker));
}

function baseCredential(overrides = {}) {
  return {
    password_hash: 'scrypt$N=16384,r=8,p=1$fixturesalt$fixturehash',
    session_generation: 7,
    failed_attempts: 3,
    locked_until: '2026-01-01T00:00:00.000Z',
    must_change: true,
    ...overrides,
  };
}

function fixtureUser(overrides = {}) {
  return {
    id: 'usr_accessibility_fixture',
    tenant_id: ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
    email: ACCESSIBILITY_PASSWORD_RESET_EMAIL,
    status: 'active',
    credential: baseCredential(),
    ...overrides,
  };
}

function resetUserFixture() {
  // Postcondition-conformant state: lockout cleared, no pending change, generation +1.
  return fixtureUser({ credential: baseCredential({
    session_generation: 8,
    failed_attempts: 0,
    locked_until: null,
    must_change: false,
  }) });
}

function createStubRuntime(overrides = {}) {
  const calls = {
    findUsersByEmail: [],
    issuePasswordInvite: [],
    setPasswordWithInvite: [],
    close: 0,
  };
  const userQueue = overrides.users ?? [[fixtureUser()], [resetUserFixture()]];
  const invite = overrides.invite ?? { token: FIXTURE_INVITE_TOKEN };
  const runtime = {
    calls,
    invite,
    repositories: {
      passwordAuth: {
        findUsersByEmail: async (...args) => {
          calls.findUsersByEmail.push(args);
          if (overrides.findUsersByEmailError) throw overrides.findUsersByEmailError;
          if (userQueue.length === 0) throw new Error('unexpected extra findUsersByEmail call');
          return userQueue.shift();
        },
      },
    },
    services: {
      passwordAuth: {
        issuePasswordInvite: async (args) => {
          calls.issuePasswordInvite.push(args);
          if (overrides.issuePasswordInviteError) throw overrides.issuePasswordInviteError;
          return invite;
        },
        setPasswordWithInvite: async (args, opts) => {
          // `snapshot` freezes the call-time values (strings are immutable), while `live`
          // stays aliased so tests can prove the operator's finally-scrubbing.
          calls.setPasswordWithInvite.push({ snapshot: { ...args }, live: args, opts });
          if (overrides.setPasswordWithInviteError) throw overrides.setPasswordWithInviteError;
          return overrides.setOutcome ?? { status: 'password_set' };
        },
      },
    },
    close: async () => {
      calls.close += 1;
      if (overrides.closeError) throw overrides.closeError;
    },
  };
  return runtime;
}

async function runReset({
  password = FIXTURE_PASSWORD,
  stream,
  env = { [RUNNER_PASSWORD_ENV_KEY]: FIXTURE_PASSWORD },
  runtimeOverrides = {},
  createRuntimeError = null,
  deps = {},
} = {}) {
  const createdEnvs = [];
  const runtime = createStubRuntime(runtimeOverrides);
  const createRuntimeFn = async (runtimeEnv, options) => {
    createdEnvs.push({ env: { ...runtimeEnv }, options: { ...options } });
    if (createRuntimeError) throw createRuntimeError;
    return runtime;
  };
  let error = null;
  let metadata = null;
  try {
    metadata = await resetAccessibilityRunnerPassword(env, {
      stdin: stream ?? framedStream(password),
      createPostgresRuntimeFn: createRuntimeFn,
      ...deps,
    });
  } catch (caught) {
    error = caught;
  }
  return { metadata, error, runtime, createdEnvs };
}

function assertFailedWith(result, code) {
  assert.ok(result.error, 'expected the orchestration to fail');
  assert.equal(result.error.code, code);
  assert.equal(result.error.message, code);
}

describe('accessibility runner password reset operator', () => {
  describe('framing', () => {
    it('accepts exactly one valid framed password', async () => {
      const password = await readFramedAccessibilityPassword(framedStream(FIXTURE_PASSWORD));
      assert.equal(password, FIXTURE_PASSWORD);
    });

    it('reassembles a frame delivered in fragmented chunks', async () => {
      const payload = Buffer.from(`${FIXTURE_PASSWORD}\n${ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER}\n`, 'utf8');
      const chunks = [];
      for (const byte of payload) chunks.push(Buffer.from([byte]));
      const password = await readFramedAccessibilityPassword(Readable.from(chunks));
      assert.equal(password, FIXTURE_PASSWORD);
    });

    it('rejects a wrong trailer marker before any runtime exists', async () => {
      const result = await runReset({
        stream: framedStream(FIXTURE_PASSWORD, { marker: 'astranull-some-other-marker-v9' }),
      });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects truncated input missing the trailer', async () => {
      const result = await runReset({ stream: Readable.from([Buffer.from(`${FIXTURE_PASSWORD}\n`, 'utf8')]) });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects empty input', async () => {
      const result = await runReset({ stream: Readable.from([]) });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects an empty password (leading line feed)', async () => {
      const result = await runReset({
        stream: Readable.from([Buffer.from(`\n${ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER}\n`, 'utf8')]),
      });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects CR bytes inside the password', async () => {
      const result = await runReset({
        stream: framedStream('cr-injected\r-password'),
      });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects NUL bytes inside the password', async () => {
      const result = await runReset({
        stream: Readable.from([Buffer.from(`nul\x00injected\n${ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER}\n`, 'utf8')]),
      });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('rejects invalid UTF-8 password bytes', async () => {
      const result = await runReset({
        stream: Readable.from([Buffer.from(`ff\xC3\x28\n${ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER}\n`, 'latin1')]),
      });
      assertFailedWith(result, 'accessibility_password_reset_framing_invalid');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('aborts oversize input with the dedicated code before the runtime exists', async () => {
      const result = await runReset({
        stream: Readable.from([Buffer.alloc(300, 0x61)]),
      });
      assertFailedWith(result, 'accessibility_password_reset_input_oversized');
      assert.equal(result.createdEnvs.length, 0);
    });

    it('accepts a 200-byte password and rejects 201 bytes at the parse boundary', async () => {
      const max = 'K'.repeat(200);
      assert.equal(await readFramedAccessibilityPassword(framedStream(max)), max);
      const tooLong = `${'K'.repeat(201)}\n${ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER}\n`;
      await assert.rejects(
        readFramedAccessibilityPassword(Readable.from([Buffer.from(tooLong, 'utf8')])),
        (error) => error.code === 'accessibility_password_reset_framing_invalid',
      );
    });

    it('zeroes every collected and concatenated buffer in a real finally path', () => {
      // The buffers are private copies, so zeroing itself is proven at the source level:
      // the finally must cover the collected chunks and the concatenated frame on every
      // path (success, framing failure, oversize, stream error).
      const reader = OPERATOR_SOURCE.match(
        /export async function readFramedAccessibilityPassword[\s\S]*?\n\}\n/,
      )?.[0];
      assert.ok(reader, 'reader source not found');
      assert.match(reader, /\} finally \{/);
      assert.match(reader, /for \(const chunk of chunks\) \{\s*\n\s*chunk\.fill\(0\);\s*\n\s*\}/);
      assert.match(reader, /chunks\.length = 0;/);
      assert.match(reader, /concatenated\?\.fill\(0\);/);
      // Zeroing happens in the outermost finally, after parse/return, not on a lucky path.
      const finallyIndex = reader.indexOf('} finally {');
      assert.ok(finallyIndex > reader.indexOf('return parseFramedAccessibilityPassword'));
    });
  });

  describe('environment hygiene', () => {
    it('deletes the password env and the auto-migrate override before runtime creation', async () => {
      const env = {
        [RUNNER_PASSWORD_ENV_KEY]: FIXTURE_PASSWORD,
        [AUTO_MIGRATE_ENV_KEY]: '1',
        ASTRANULL_DATABASE_URL: 'postgresql://fixture.invalid/astranull',
      };
      const result = await runReset({ env });
      assert.ok(result.metadata, 'expected success');
      assert.equal(result.createdEnvs.length, 1);
      const created = result.createdEnvs[0];
      assert.ok(!(RUNNER_PASSWORD_ENV_KEY in created.env), 'runtime env must not carry the password');
      assert.ok(!(AUTO_MIGRATE_ENV_KEY in created.env), 'runtime env must not carry the auto-migrate override');
      assert.equal(created.options.autoMigrate, false, 'runtime must be created with autoMigrate:false');
      assert.ok(
        !(RUNNER_PASSWORD_ENV_KEY in env),
        'the supplied env object itself must lose the password key immediately',
      );
    });

    it('loses the password env even when runtime creation fails', async () => {
      const env = { [RUNNER_PASSWORD_ENV_KEY]: FIXTURE_PASSWORD };
      const result = await runReset({ env, createRuntimeError: new Error('boom-fixture') });
      assertFailedWith(result, 'accessibility_password_reset_runtime_unavailable');
      assert.equal(result.createdEnvs.length, 1);
      assert.ok(!(RUNNER_PASSWORD_ENV_KEY in env));
      assert.ok(!(AUTO_MIGRATE_ENV_KEY in result.createdEnvs[0].env));
    });

    it('prepareAccessibilityPasswordResetEnvironment never copies the secret forward', () => {
      const env = { [RUNNER_PASSWORD_ENV_KEY]: FIXTURE_PASSWORD, [AUTO_MIGRATE_ENV_KEY]: '1', KEEP: 'yes' };
      const runtimeEnv = prepareAccessibilityPasswordResetEnvironment(env);
      assert.ok(!(RUNNER_PASSWORD_ENV_KEY in runtimeEnv));
      assert.ok(!(AUTO_MIGRATE_ENV_KEY in runtimeEnv));
      assert.equal(runtimeEnv.KEEP, 'yes');
      assert.ok(!(RUNNER_PASSWORD_ENV_KEY in env));
    });
  });

  describe('policy pre-assessment', () => {
    it('rejects a weak password with no invite, no set, and no account lookup', async () => {
      const result = await runReset({ password: WEAK_PASSWORD });
      assertFailedWith(result, 'accessibility_password_reset_password_policy_rejected');
      assert.equal(result.createdEnvs.length, 1, 'runtime creation before assessment is acceptable');
      assert.equal(result.runtime.calls.issuePasswordInvite.length, 0, 'no invite on weak input');
      assert.equal(result.runtime.calls.setPasswordWithInvite.length, 0, 'no write on weak input');
      assert.equal(result.runtime.calls.findUsersByEmail.length, 0);
      assert.equal(result.runtime.calls.close, 1, 'runtime must still be closed');
    });

    it('rejects a password containing the account email local part', async () => {
      const result = await runReset({ password: 'accessibility-runner-9X!' });
      assertFailedWith(result, 'accessibility_password_reset_password_policy_rejected');
      assert.equal(result.runtime.calls.issuePasswordInvite.length, 0);
    });
  });

  describe('account resolution', () => {
    it('looks the account up by the exact tenant and email pair', async () => {
      const result = await runReset();
      assert.ok(result.metadata);
      assert.deepEqual(result.runtime.calls.findUsersByEmail[0], [
        ACCESSIBILITY_PASSWORD_RESET_EMAIL,
        ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
      ]);
      assert.deepEqual(result.runtime.calls.findUsersByEmail[1], [
        ACCESSIBILITY_PASSWORD_RESET_EMAIL,
        ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
      ]);
    });

    it('fails closed on a missing account', async () => {
      const result = await runReset({ runtimeOverrides: { users: [[], []] } });
      assertFailedWith(result, 'accessibility_password_reset_account_not_found');
      assert.equal(result.runtime.calls.issuePasswordInvite.length, 0);
    });

    it('fails closed on an ambiguous account', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser(), fixtureUser({ id: 'usr_second' })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_account_ambiguous');
      assert.equal(result.runtime.calls.issuePasswordInvite.length, 0);
    });

    it('fails closed on a wrong-email row even if tenant matches', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ email: 'someone-else@astranull.invalid' })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_account_not_found');
    });

    it('fails closed on a wrong-tenant row even if email matches', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ tenant_id: 'ten_other' })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_account_not_found');
    });

    it('fails closed on an inactive account', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ status: 'disabled' })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_account_inactive');
      assert.equal(result.runtime.calls.issuePasswordInvite.length, 0);
    });

    it('fails closed when the credential is missing', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ credential: null })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_credential_missing');
    });

    it('fails closed when the password hash is absent', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ credential: baseCredential({ password_hash: '' }) })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_credential_missing');
    });

    it('fails closed when the session generation is not a safe integer', async () => {
      const result = await runReset({
        runtimeOverrides: { users: [[fixtureUser({ credential: baseCredential({ session_generation: '7' }) })], []] },
      });
      assertFailedWith(result, 'accessibility_password_reset_credential_missing');
    });
  });

  describe('successful reset', () => {
    it('issues a 60-second invite and sets the password with the fixed client key', async () => {
      const result = await runReset();
      assert.ok(result.metadata);
      const invite = result.runtime.calls.issuePasswordInvite[0];
      assert.equal(invite.tenantId, ACCESSIBILITY_PASSWORD_RESET_TENANT_ID);
      assert.equal(invite.userId, 'usr_accessibility_fixture');
      assert.equal(invite.createdBy, ACCESSIBILITY_PASSWORD_RESET_OPERATOR_CREATED_BY);
      assert.equal(invite.ttlMs, ACCESSIBILITY_PASSWORD_RESET_INVITE_TTL_MS);
      assert.equal(invite.ttlMs, 60_000);

      const record = result.runtime.calls.setPasswordWithInvite[0];
      assert.equal(record.opts.clientKey, ACCESSIBILITY_PASSWORD_RESET_CLIENT_KEY);
      assert.equal(record.snapshot.password, FIXTURE_PASSWORD, 'the set call must receive the framed password');
      assert.equal(record.snapshot.token, FIXTURE_INVITE_TOKEN, 'the set call must receive the invite token');
    });

    it('returns metadata-only success output with the password_reset status', async () => {
      const result = await runReset();
      const metadata = result.metadata;
      assert.deepEqual(metadata, {
        status: 'password_reset',
        tenant_id: ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
        user_id: 'usr_accessibility_fixture',
        email: ACCESSIBILITY_PASSWORD_RESET_EMAIL,
        session_generation_rotated: true,
        password_sessions_invalidated: true,
        lockout_cleared: true,
      });
      const serialized = JSON.stringify(metadata);
      assert.ok(!serialized.includes(FIXTURE_PASSWORD), 'metadata must not carry the password');
      assert.ok(!serialized.includes(FIXTURE_INVITE_TOKEN), 'metadata must not carry the invite token');
    });

    it('proves the lockout, must-change, and generation-rotation postconditions', async () => {
      const result = await runReset();
      assert.ok(result.metadata, 'conforming post-reset state must pass');
      assert.equal(result.runtime.calls.findUsersByEmail.length, 2);
    });

    it('fails closed when the generation did not advance by exactly one', async () => {
      const result = await runReset({
        runtimeOverrides: {
          users: [
            [fixtureUser()],
            [fixtureUser({ credential: baseCredential({
              session_generation: 9,
              failed_attempts: 0,
              locked_until: null,
              must_change: false,
            }) })],
          ],
        },
      });
      assertFailedWith(result, 'accessibility_password_reset_postcondition_failed');
    });

    it('fails closed when the lockout was not cleared', async () => {
      const result = await runReset({
        runtimeOverrides: {
          users: [
            [fixtureUser()],
            [fixtureUser({ credential: baseCredential({
              session_generation: 8,
              failed_attempts: 0,
              locked_until: '2027-01-01T00:00:00.000Z',
              must_change: false,
            }) })],
          ],
        },
      });
      assertFailedWith(result, 'accessibility_password_reset_postcondition_failed');
    });

    it('fails closed when failed attempts were not reset', async () => {
      const result = await runReset({
        runtimeOverrides: {
          users: [
            [fixtureUser()],
            [fixtureUser({ credential: baseCredential({
              session_generation: 8,
              failed_attempts: 1,
              locked_until: null,
              must_change: false,
            }) })],
          ],
        },
      });
      assertFailedWith(result, 'accessibility_password_reset_postcondition_failed');
    });

    it('fails closed when must_change is still set', async () => {
      const result = await runReset({
        runtimeOverrides: {
          users: [
            [fixtureUser()],
            [fixtureUser({ credential: baseCredential({
              session_generation: 8,
              failed_attempts: 0,
              locked_until: null,
              must_change: true,
            }) })],
          ],
        },
      });
      assertFailedWith(result, 'accessibility_password_reset_postcondition_failed');
    });

    it('clears the mutable invite-token and password carriers in a finally', async () => {
      const result = await runReset();
      assert.ok(result.metadata);
      // The invite object is the same instance the stub returned; the operator must have
      // nulled its token, and the live set-args carrier must be scrubbed too.
      assert.equal(result.runtime.invite.token, null);
      const record = result.runtime.calls.setPasswordWithInvite[0];
      assert.equal(record.live.token, null);
      assert.equal(record.live.password, null);
    });

    it('clears the invite secret even when the set call throws', async () => {
      const result = await runReset({
        runtimeOverrides: { setPasswordWithInviteError: new Error('set-boom-fixture') },
      });
      assert.ok(result.error);
      assert.equal(resolveAccessibilityPasswordResetErrorCode(result.error), 'accessibility_password_reset_failed');
      assert.equal(result.runtime.invite.token, null);
      const record = result.runtime.calls.setPasswordWithInvite[0];
      assert.equal(record.live.token, null);
      assert.equal(record.live.password, null);
      assert.equal(result.runtime.calls.close, 1);
    });
  });

  describe('runtime lifecycle', () => {
    it('closes the runtime exactly once on success', async () => {
      const result = await runReset();
      assert.ok(result.metadata);
      assert.equal(result.runtime.calls.close, 1);
    });

    it('closes the runtime exactly once when a write fails', async () => {
      const result = await runReset({
        runtimeOverrides: { issuePasswordInviteError: new Error('invite-boom-fixture') },
      });
      assert.ok(result.error);
      assert.equal(result.runtime.calls.close, 1);
    });

    it('maps unexpected write failures to the generic allowlisted code', async () => {
      const result = await runReset({
        runtimeOverrides: { findUsersByEmailError: new Error('raw database text fixture') },
      });
      assert.ok(result.error);
      assert.equal(resolveAccessibilityPasswordResetErrorCode(result.error), 'accessibility_password_reset_failed');
    });

    it('fails safely when closing the runtime fails after a successful reset', async () => {
      const result = await runReset({ runtimeOverrides: { closeError: new Error('close-boom-fixture') } });
      assertFailedWith(result, 'accessibility_password_reset_runtime_unavailable');
      assert.equal(result.metadata, null, 'a close failure must suppress the success metadata');
      assert.equal(result.runtime.calls.close, 1);
    });

    it('fails safely when closing the runtime also fails on a failure path', async () => {
      const result = await runReset({
        runtimeOverrides: {
          issuePasswordInviteError: new Error('invite-boom-fixture'),
          closeError: new Error('close-boom-fixture'),
        },
      });
      assertFailedWith(result, 'accessibility_password_reset_runtime_unavailable');
      assert.equal(result.runtime.calls.close, 1);
    });

    it('reports runtime_unavailable when the runtime lacks the required contract', async () => {
      const result = await runReset({ runtimeOverrides: {} });
      // Replace the stub functions with a contract-less runtime.
      const broken = await resetAccessibilityRunnerPassword(
        { [RUNNER_PASSWORD_ENV_KEY]: FIXTURE_PASSWORD },
        {
          stdin: framedStream(FIXTURE_PASSWORD),
          createPostgresRuntimeFn: async () => ({ close: async () => {} }),
        },
      ).catch((error) => error);
      assert.equal(broken.code, 'accessibility_password_reset_runtime_unavailable');
      assert.ok(result);
    });
  });

  describe('failure surface', () => {
    it('exposes only allowlisted codes with the code as the message', () => {
      for (const code of ACCESSIBILITY_PASSWORD_RESET_ERROR_CODES) {
        const failure = createAccessibilityPasswordResetFailure(code);
        assert.equal(failure.message, code);
        assert.equal(resolveAccessibilityPasswordResetErrorCode(failure), code);
      }
      assert.equal(
        resolveAccessibilityPasswordResetErrorCode(new Error('anything else')),
        'accessibility_password_reset_failed',
      );
      assert.equal(resolveAccessibilityPasswordResetErrorCode(undefined), 'accessibility_password_reset_failed');
    });

    it('keeps main-facing output metadata-only at the source level', () => {
      // stdout: exactly one write, and it serializes the metadata object only.
      const stdoutWrites = OPERATOR_SOURCE.match(/process\.stdout\.write\([^;]*\);/g) ?? [];
      assert.equal(stdoutWrites.length, 1);
      assert.match(stdoutWrites[0], /JSON\.stringify\(metadata\)/);
      // stderr: exactly one write, and it emits only the resolved allowlisted code.
      const stderrWrites = OPERATOR_SOURCE.match(/process\.stderr\.write\([^;]*\);/g) ?? [];
      assert.equal(stderrWrites.length, 1);
      assert.match(stderrWrites[0], /code/);
      assert.doesNotMatch(OPERATOR_SOURCE, /console\./);
      assert.doesNotMatch(OPERATOR_SOURCE, /process\.exit\(1\)/);
    });
  });
});

describe('accessibility password reset static contract', () => {
  it('operator script passes node --check', () => {
    const result = spawnSync('node', ['--check', OPERATOR_PATH], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  });

  it('wrapper script passes bash -n', () => {
    const result = spawnSync('bash', ['-n', WRAPPER_PATH], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  });

  it('workflow YAML parses (same gate as CI)', () => {
    const result = spawnSync(
      'ruby',
      ['-ryaml', '-e', "YAML.parse_file('.github/workflows/reset-accessibility-password.yml')"],
      { cwd: ROOT, encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
  });

  it('workflow structure: dispatch, production environment, shared concurrency, pinned checkout', () => {
    const parsed = JSON.parse(
      spawnSync('ruby', ['-ryaml', '-rjson', '-e', 'print YAML.load_file(ARGV[0]).to_json', WORKFLOW_PATH], {
        cwd: ROOT,
        encoding: 'utf8',
      }).stdout,
    );
    // Psych resolves the bare `on` key to boolean true; GitHub treats both the same.
    const trigger = parsed['true'] ?? parsed.on;
    assert.ok(trigger, 'workflow trigger missing');
    assert.deepEqual(Object.keys(trigger), ['workflow_dispatch']);
    const inputs = trigger.workflow_dispatch.inputs;
    assert.deepEqual(Object.keys(inputs), ['release_sha'], 'workflow must accept only release_sha');
    assert.equal(inputs.release_sha.required, true);
    assert.equal(inputs.release_sha.type, 'string');

    assert.equal(parsed['concurrency'].group, 'deploy-aws');
    assert.equal(parsed['concurrency']['cancel-in-progress'], false);
    assert.deepEqual(parsed.permissions, { contents: 'read' });

    const job = parsed.jobs.reset;
    assert.equal(job['if'], "github.ref == 'refs/heads/main'");
    assert.equal(job.environment, 'production');

    const checkout = job.steps.find((step) => String(step.uses ?? '').startsWith('actions/checkout@'));
    assert.ok(checkout, 'checkout step missing');
    assert.match(checkout.uses, /^actions\/checkout@[0-9a-f]{40}( |$)/, 'checkout must be SHA-pinned');
    assert.equal(checkout.with.ref, '${{ inputs.release_sha }}');
    assert.equal(checkout.with['persist-credentials'], false);
  });

  it('workflow and wrapper never enable shell tracing', () => {
    for (const [name, source] of [['workflow', WORKFLOW_SOURCE], ['wrapper', WRAPPER_SOURCE]]) {
      assert.doesNotMatch(source, /set\s+-[A-Za-z]*x/, `${name} must not enable set -x`);
      assert.doesNotMatch(source, /\bset\s+-x\b/, `${name} must not enable set -x`);
    }
  });

  it('password appears only in its allowlisted contexts and never leaves the framed stdin pipe', () => {
    const lines = WORKFLOW_SOURCE.split('\n');
    const contexts = [
      // Step env mapping from the repository secret.
      { match: /^\s*ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD: \$\{\{ secrets\.ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD \}\}$/, max: 1 },
      // Required-input guard.
      { match: /^\s*: "\$\{ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD:\?missing accessibility runner password\}"$/, max: 1 },
      // The single framed stdin pipe.
      { match: /^\s*reset_metadata=\$\(printf '%s\\n[0-9a-z-]+\\n' "\$ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD" \| \\$/, max: 1 },
      // End-of-run unset.
      { match: /^\s*unset SSH_KEY ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD$/, max: 1 },
      // Verifier reads it into a local and deletes it from process.env immediately.
      { match: /^\s*let password = process\.env\.ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD \?\? "";$/, max: 1 },
      { match: /^\s*delete process\.env\.ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD;$/, max: 1 },
    ];
    for (const line of lines) {
      if (!line.includes('ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD')) continue;
      const context = contexts.find((candidate) => candidate.match.test(line));
      assert.ok(context, `unexpected password usage: ${line.trim()}`);
      context.max -= 1;
    }
    for (const context of contexts) {
      assert.equal(context.max, 0, `expected exactly one occurrence for ${context.match}`);
    }

    // The remote ssh command string must never interpolate the password.
    const sshCommand = WORKFLOW_SOURCE.match(/"set -euo pipefail; cleanup\(\)[\s\S]*?'\$remote_state'"\)/)?.[0] ?? '';
    assert.ok(sshCommand, 'remote reset command not found');
    assert.ok(!sshCommand.includes('ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD'));
    assert.ok(!sshCommand.includes('$SSH_KEY'));
    assert.ok(!sshCommand.includes('$KNOWN_HOSTS'));
  });

  it('password is piped exactly once, framed, with the kill-after bounded ssh timeout', () => {
    const pipe = WORKFLOW_SOURCE.match(
      /printf '%s\\n[^\n']*\\n' "\$ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD" \|\s*\\\n\s*timeout -k 10 1800 ssh /,
    );
    assert.ok(pipe, 'the framed password pipe must feed a timeout -k 10 1800 ssh');
    assert.match(WORKFLOW_SOURCE, /astranull-accessibility-password-reset-v1/);
    assert.equal((WORKFLOW_SOURCE.match(/timeout -k 10 1800 ssh /g) ?? []).length, 1);
  });

  it('transfers only the three shell files and verifies their checksums remotely', () => {
    assert.match(WORKFLOW_SOURCE, /timeout -k 5 60 scp "\$\{ssh_base\[@\]\}" ops\/aws\/reset-accessibility-runner-password\.sh "\$\{user\}@\$\{HOST\}:\$\{remote_wrapper\}"/);
    assert.match(WORKFLOW_SOURCE, /timeout -k 5 60 scp "\$\{ssh_base\[@\]\}" ops\/aws\/deploy\.sh "\$\{user\}@\$\{HOST\}:\$\{remote_deploy\}"/);
    assert.match(WORKFLOW_SOURCE, /timeout -k 5 60 scp "\$\{ssh_base\[@\]\}" ops\/aws\/release-state\.sh "\$\{user\}@\$\{HOST\}:\$\{remote_state\}"/);
    assert.match(WORKFLOW_SOURCE, /sha256sum -c - >\/dev\/null; printf '%s  %s\\n' '\$deploy_sha256' '\$remote_deploy' \| sha256sum -c - >\/dev\/null/);
    assert.equal((WORKFLOW_SOURCE.match(/sha256sum -c -/g) ?? []).length, 3);
    // Strict host key pinning with a dedicated known_hosts file from the repository secret.
    assert.match(WORKFLOW_SOURCE, /-o IdentitiesOnly=yes -o StrictHostKeyChecking=yes/);
    assert.match(WORKFLOW_SOURCE, /printf '%s\\n' "\$KNOWN_HOSTS" > "\$HOME\/\.ssh\/known_hosts"; chmod 600 "\$HOME\/\.ssh\/known_hosts"/);
    // Local source integrity before transfer.
    assert.match(WORKFLOW_SOURCE, /git diff --exit-code HEAD -- "\$\{checked_files\[@\]\}"/);
    assert.match(WORKFLOW_SOURCE, /\[\[ -x ops\/aws\/reset-accessibility-runner-password\.sh \]\]/);
    // Remote cleanup covers all three transferred paths on exit.
    assert.match(WORKFLOW_SOURCE, /rm -f -- '\$remote_wrapper' '\$remote_deploy' '\$remote_state'/);
  });

  it('verifier prints one combined metadata-only line and holds no secret after use', () => {
    const verifier = WORKFLOW_SOURCE.match(/node --input-type=module -e '[\s\S]*?'\n\n\s*unset/)?.[0] ?? '';
    assert.ok(verifier, 'verifier script not found');
    assert.match(verifier, /metadata\?\.status !== "password_reset"/);
    assert.match(verifier, /password = null;/, 'password must be nulled after delivery');
    assert.match(verifier, /token = null;/, 'token must be nulled after inspection');
    assert.match(verifier, /body = null;/, 'response body reference must be dropped');
    const stdoutWrites = verifier.match(/process\.stdout\.write\([^;]*\);/g) ?? [];
    assert.equal(stdoutWrites.length, 1, 'verifier must print exactly one line');
    assert.match(stdoutWrites[0], /JSON\.stringify\(combined\)/);
    assert.match(verifier, /status: "password_reset_verified"/);
    assert.match(verifier, /login_verified: true/);
    // The combined line is built only from metadata and verified facts.
    const combined = verifier.match(/const combined = \{[\s\S]*?\};/)?.[0] ?? '';
    assert.ok(combined);
    assert.ok(!combined.includes(FIXTURE_PASSWORD));
    assert.ok(!combined.includes(FIXTURE_INVITE_TOKEN));
    assert.ok(!combined.includes('token,') && !combined.includes('access_token'));
    assert.ok(!combined.includes('body'));
  });

  it('wrapper proves the requested SHA end to end before executing the operator', () => {
    assert.match(WRAPPER_SOURCE, /\[\[ "\$REQUESTED_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/);
    // Transferred paths must embed the requested SHA itself.
    assert.ok(WRAPPER_SOURCE.includes('/tmp/astranull-deploy-${REQUESTED_SHA}-[0-9]+-[0-9]+\\.sh$'));
    assert.ok(WRAPPER_SOURCE.includes('/tmp/astranull-release-state-${REQUESTED_SHA}-[0-9]+-[0-9]+\\.sh$'));
    // Both transferred files are validated regular/non-symlink before source.
    assert.match(WRAPPER_SOURCE, /\[\[ -f "\$DEPLOY_LIB_PATH" && ! -L "\$DEPLOY_LIB_PATH" \]\]/);
    assert.match(WRAPPER_SOURCE, /\[\[ -f "\$RELEASE_STATE_LIB_PATH" && ! -L "\$RELEASE_STATE_LIB_PATH" \]\]/);
    // Reused deploy lock and exact-release proof.
    assert.match(WRAPPER_SOURCE, /acquire_deploy_lock/);
    assert.match(WRAPPER_SOURCE, /\[\[ "\$\(git rev-parse HEAD\)" == "\$REQUESTED_SHA" \]\]/);
    assert.match(WRAPPER_SOURCE, /\[\[ "\$\(git rev-parse origin\/main\)" == "\$REQUESTED_SHA" \]\]/);
    assert.match(WRAPPER_SOURCE, /\[\[ "\$release_bundle_control_tag" == "\$REQUESTED_SHA" \]\]/);
  });

  it('wrapper proves exact image identity, operator hash, app role, and non-root posture', () => {
    assert.match(WRAPPER_SOURCE, /export ASTRANULL_CONTROL_PLANE_IMAGE_ID=\$release_bundle_control_image_id/);
    assert.match(WRAPPER_SOURCE, /release_runtime_service_matches_id control-plane "\$release_bundle_control_image_id"/);
    assert.match(WRAPPER_SOURCE, /container_operator_sha256=.*sha256sum "\$OPERATOR_CONTAINER_PATH"/);
    assert.match(WRAPPER_SOURCE, /\[\[ "\$container_operator_sha256" == "\$OPERATOR_SHA256" \]\]/);
    assert.match(WRAPPER_SOURCE, /\[ "\$\(id -u\)" = 10001 \]/);
    assert.match(WRAPPER_SOURCE, /\[ "\$\(id -g\)" = 10001 \]/);
    assert.match(WRAPPER_SOURCE, /postgresql:\/\/astranull_app:/);
    assert.match(WRAPPER_SOURCE, /\[ "\$\{ASTRANULL_ENFORCE_DATABASE_ROLE-\}" = 1 \]/);
    assert.match(WRAPPER_SOURCE, /echo 'reset: control-plane process posture verification failed/);
  });

  it('wrapper keeps stdin untouched, reuses snapshot cleanup, and never sees the password', () => {
    // Snapshot cleanup is acquired, pending-flagged, and trap-driven.
    assert.match(WRAPPER_SOURCE, /RESET_SNAPSHOT_CLEANUP_PENDING=1/);
    assert.match(WRAPPER_SOURCE, /snapshot_env_file/);
    assert.match(WRAPPER_SOURCE, /cleanup_compose_snapshots/);
    assert.match(WRAPPER_SOURCE, /trap reset_cleanup EXIT/);
    // stdin is consumed only by the final bounded exec; no host command reads it.
    assert.match(WRAPPER_SOURCE, /exec timeout -k 30 600 docker exec -i --user 10001:10001 "\$control_cid" \\\n\s*node "\$OPERATOR_CONTAINER_PATH"/);
    assert.equal((WRAPPER_SOURCE.match(/docker exec -i /g) ?? []).length, 1);
    assert.doesNotMatch(WRAPPER_SOURCE, /\bread\b/);
    assert.doesNotMatch(WRAPPER_SOURCE, /\bcat\b/);
    // The password never exists on the host side: no env reference, no argv, no temp file.
    assert.ok(!WRAPPER_SOURCE.includes('ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD'));
    assert.ok(!WRAPPER_SOURCE.includes('PASSWORD'));
    assert.doesNotMatch(WRAPPER_SOURCE, /mktemp/);
  });

  it('CI continues to gate the operator, wrapper, and workflow syntax', () => {
    assert.match(CI_SOURCE, /YAML\.parse_file\('\.github\/workflows\/reset-accessibility-password\.yml'\)/);
    assert.match(CI_SOURCE, /bash -n ops\/aws\/reset-accessibility-runner-password\.sh/);
    assert.match(CI_SOURCE, /node --check scripts\/reset-accessibility-runner-password\.mjs/);
    assert.match(CI_SOURCE, /node --test tests\/unit\/\*\.test\.mjs/);
  });
});
