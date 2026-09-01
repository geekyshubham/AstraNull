#!/usr/bin/env node
// One-shot password reset operator for the fixed accessibility automation account.
// Runs inside the deployed control-plane container as uid/gid 10001. The password is
// delivered exactly once over stdin with the framing below and is never echoed, logged,
// returned, or written to disk. Stdout carries one metadata-only JSON line; every
// failure exits non-zero with a single allowlisted generic code.
//
// stdin framing (total input is bounded and must match exactly):
//   <password bytes, 1..200, UTF-8, no CR/LF/NUL> LF
//   astranull-accessibility-password-reset-v1 LF
//   EOF

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assessPassword } from '../src/lib/password.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

export const ACCESSIBILITY_PASSWORD_RESET_TENANT_ID = 'ten_demo';
export const ACCESSIBILITY_PASSWORD_RESET_EMAIL = 'accessibility-runner@astranull.invalid';
export const ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER =
  'astranull-accessibility-password-reset-v1';
export const ACCESSIBILITY_PASSWORD_RESET_MAX_INPUT_BYTES = 256;
export const ACCESSIBILITY_PASSWORD_RESET_MAX_PASSWORD_BYTES = 200;
export const ACCESSIBILITY_PASSWORD_RESET_INVITE_TTL_MS = 60_000;
export const ACCESSIBILITY_PASSWORD_RESET_OPERATOR_CREATED_BY =
  'astranull-accessibility-automation';
export const ACCESSIBILITY_PASSWORD_RESET_CLIENT_KEY = 'accessibility-password-reset-exec';

export const ACCESSIBILITY_PASSWORD_RESET_ERROR_CODES = Object.freeze([
  'accessibility_password_reset_failed',
  'accessibility_password_reset_framing_invalid',
  'accessibility_password_reset_input_oversized',
  'accessibility_password_reset_password_policy_rejected',
  'accessibility_password_reset_runtime_unavailable',
  'accessibility_password_reset_account_not_found',
  'accessibility_password_reset_account_ambiguous',
  'accessibility_password_reset_account_inactive',
  'accessibility_password_reset_credential_missing',
  'accessibility_password_reset_invite_failed',
  'accessibility_password_reset_set_failed',
  'accessibility_password_reset_postcondition_failed',
]);

const RUNNER_PASSWORD_ENV_KEY = 'ASTRANULL_ACCESSIBILITY_RUNNER_PASSWORD';
const AUTO_MIGRATE_ENV_KEY = 'ASTRANULL_POSTGRES_AUTO_MIGRATE';

export function createAccessibilityPasswordResetFailure(code) {
  // The message is the code itself: no failure path may smuggle raw error text,
  // SQL, or database URLs out of this process.
  const error = new Error(code);
  error.code = code;
  return error;
}

export function resolveAccessibilityPasswordResetErrorCode(error) {
  return ACCESSIBILITY_PASSWORD_RESET_ERROR_CODES.includes(error?.code)
    ? error.code
    : 'accessibility_password_reset_failed';
}

function deleteEnvKey(env, key) {
  if (env == null || typeof env !== 'object') return;
  try {
    delete env[key];
  } catch {
    // A frozen environment cannot retain the secret either; the copy below is authoritative.
  }
}

/**
 * Removes the runner password from the supplied environment immediately and returns a
 * copy with both the password and the auto-migration override deleted, so the runtime
 * is always created with an explicit autoMigrate:false contract.
 */
export function prepareAccessibilityPasswordResetEnvironment(env) {
  deleteEnvKey(env, RUNNER_PASSWORD_ENV_KEY);
  const runtimeEnv = { ...(env ?? {}) };
  delete runtimeEnv[RUNNER_PASSWORD_ENV_KEY];
  delete runtimeEnv[AUTO_MIGRATE_ENV_KEY];
  return runtimeEnv;
}

function parseFramedAccessibilityPassword(buffer, {
  marker = ACCESSIBILITY_PASSWORD_RESET_FRAMING_MARKER,
  maxPasswordBytes = ACCESSIBILITY_PASSWORD_RESET_MAX_PASSWORD_BYTES,
} = {}) {
  const framingInvalid = () =>
    createAccessibilityPasswordResetFailure('accessibility_password_reset_framing_invalid');
  const separator = buffer.indexOf(0x0a);
  if (separator < 1) throw framingInvalid();
  const passwordBytes = buffer.subarray(0, separator);
  const trailer = buffer.subarray(separator + 1);
  if (
    trailer.byteLength !== marker.length + 1
    || trailer[marker.length] !== 0x0a
    || !trailer.subarray(0, marker.length).equals(Buffer.from(marker, 'utf8'))
  ) {
    throw framingInvalid();
  }
  if (passwordBytes.byteLength > maxPasswordBytes) throw framingInvalid();
  if (passwordBytes.includes(0x00) || passwordBytes.includes(0x0d)) throw framingInvalid();
  let password;
  try {
    password = new TextDecoder('utf-8', { fatal: true }).decode(passwordBytes);
  } catch {
    throw framingInvalid();
  }
  return password;
}

/**
 * Reads exactly one framed password from the stream. Total input is bounded; an
 * oversize stream aborts as soon as the bound is exceeded.
 */
export async function readFramedAccessibilityPassword(stream, options = {}) {
  const maxInputBytes = options.maxInputBytes ?? ACCESSIBILITY_PASSWORD_RESET_MAX_INPUT_BYTES;
  const chunks = [];
  let concatenated = null;
  try {
    let total = 0;
    try {
      for await (const chunk of stream) {
        const collected = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += collected.byteLength;
        if (total > maxInputBytes) {
          collected.fill(0);
          throw createAccessibilityPasswordResetFailure('accessibility_password_reset_input_oversized');
        }
        chunks.push(collected);
      }
    } catch (error) {
      if (ACCESSIBILITY_PASSWORD_RESET_ERROR_CODES.includes(error?.code)) throw error;
      throw createAccessibilityPasswordResetFailure('accessibility_password_reset_framing_invalid');
    }
    concatenated = Buffer.concat(chunks);
    return parseFramedAccessibilityPassword(concatenated, options);
  } finally {
    // Best-effort zeroing on every path (success, framing failure, oversize, stream
    // error): no collected or concatenated copy of the secret bytes may outlive this
    // call. The decoded password itself is the one unavoidable short-lived JS string.
    for (const chunk of chunks) {
      chunk.fill(0);
    }
    chunks.length = 0;
    concatenated?.fill(0);
  }
}

function assertSingleAccessibilityRunner(users) {
  const notFound = () =>
    createAccessibilityPasswordResetFailure('accessibility_password_reset_account_not_found');
  if (!Array.isArray(users) || users.length === 0) throw notFound();
  if (users.length > 1) {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_account_ambiguous');
  }
  const user = users[0];
  if (
    user?.tenant_id !== ACCESSIBILITY_PASSWORD_RESET_TENANT_ID
    || user?.email !== ACCESSIBILITY_PASSWORD_RESET_EMAIL
  ) {
    throw notFound();
  }
  if (user.status !== 'active') {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_account_inactive');
  }
  const credential = user.credential ?? null;
  if (
    !credential
    || typeof credential.password_hash !== 'string'
    || credential.password_hash.length === 0
    || !Number.isSafeInteger(credential.session_generation)
  ) {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_credential_missing');
  }
  return user;
}

function assertPostconditions(after, user, previousGeneration) {
  const next = after?.length === 1 ? after[0] : null;
  const credential = next?.credential ?? null;
  if (
    next?.id !== user.id
    || next?.tenant_id !== ACCESSIBILITY_PASSWORD_RESET_TENANT_ID
    || next?.email !== ACCESSIBILITY_PASSWORD_RESET_EMAIL
    || next?.status !== 'active'
    || credential?.session_generation !== previousGeneration + 1
    || credential?.failed_attempts !== 0
    || credential?.locked_until != null
    || credential?.must_change !== false
  ) {
    throw createAccessibilityPasswordResetFailure(
      'accessibility_password_reset_postcondition_failed',
    );
  }
}

async function applyAccessibilityPasswordReset(runtime, password, deps = {}) {
  const assess = deps.assessPasswordFn ?? assessPassword;
  const repositories = runtime?.repositories;
  const services = runtime?.services;
  if (
    typeof repositories?.passwordAuth?.findUsersByEmail !== 'function'
    || typeof services?.passwordAuth?.issuePasswordInvite !== 'function'
    || typeof services?.passwordAuth?.setPasswordWithInvite !== 'function'
  ) {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_runtime_unavailable');
  }

  // Pre-assess the shared password policy before any write path is opened.
  const assessment = assess(password, { email: ACCESSIBILITY_PASSWORD_RESET_EMAIL });
  if (!assessment?.ok) {
    throw createAccessibilityPasswordResetFailure(
      'accessibility_password_reset_password_policy_rejected',
    );
  }

  const before = await repositories.passwordAuth.findUsersByEmail(
    ACCESSIBILITY_PASSWORD_RESET_EMAIL,
    ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
  );
  const user = assertSingleAccessibilityRunner(before);
  const previousGeneration = user.credential.session_generation;

  const invite = await services.passwordAuth.issuePasswordInvite({
    tenantId: ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
    userId: user.id,
    createdBy: ACCESSIBILITY_PASSWORD_RESET_OPERATOR_CREATED_BY,
    ttlMs: ACCESSIBILITY_PASSWORD_RESET_INVITE_TTL_MS,
  });
  if (typeof invite?.token !== 'string' || invite.token.length === 0) {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_invite_failed');
  }

  // Mutable carriers of the invite secret and password are cleared in the finally
  // below whether the call succeeds, fails, or throws.
  let setPasswordArgs = { token: invite.token, password };
  let outcome;
  try {
    outcome = await services.passwordAuth.setPasswordWithInvite(
      setPasswordArgs,
      { clientKey: ACCESSIBILITY_PASSWORD_RESET_CLIENT_KEY },
    );
  } finally {
    // Drop the one-time invite secret and every mutable password reference.
    invite.token = null;
    setPasswordArgs.token = null;
    setPasswordArgs.password = null;
    setPasswordArgs = null;
  }
  if (!outcome || outcome.error || outcome.status !== 'password_set') {
    throw createAccessibilityPasswordResetFailure('accessibility_password_reset_set_failed');
  }

  const after = await repositories.passwordAuth.findUsersByEmail(
    ACCESSIBILITY_PASSWORD_RESET_EMAIL,
    ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
  );
  assertPostconditions(after, user, previousGeneration);

  return {
    status: 'password_reset',
    tenant_id: ACCESSIBILITY_PASSWORD_RESET_TENANT_ID,
    user_id: user.id,
    email: ACCESSIBILITY_PASSWORD_RESET_EMAIL,
    session_generation_rotated: true,
    password_sessions_invalidated: true,
    lockout_cleared: true,
  };
}

async function closeAccessibilityRuntime(runtime) {
  try {
    await runtime?.close?.();
    return true;
  } catch {
    return false;
  }
}

/**
 * Injectable orchestration used by unit tests. `env` is treated as owned by this
 * function: the runner password key is deleted from it immediately.
 */
export async function resetAccessibilityRunnerPassword(env, deps = {}) {
  const createRuntime = deps.createPostgresRuntimeFn ?? createPostgresRuntime;
  const stdin = deps.stdin ?? process.stdin;
  const runtimeEnv = prepareAccessibilityPasswordResetEnvironment(env);
  let password = null;
  try {
    // Framing failures happen before any database work and before the runtime exists.
    password = await readFramedAccessibilityPassword(stdin, deps.framing);

    let runtime;
    try {
      runtime = await createRuntime(runtimeEnv, { autoMigrate: false });
    } catch {
      throw createAccessibilityPasswordResetFailure('accessibility_password_reset_runtime_unavailable');
    }

    try {
      // Metadata is the only value that leaves this function; the password never does.
      return await applyAccessibilityPasswordReset(runtime, password, deps);
    } finally {
      // Closure is a real finally path for every success and failure after
      // initialization, and a close failure fails safely by replacing the outcome.
      if (!(await closeAccessibilityRuntime(runtime))) {
        throw createAccessibilityPasswordResetFailure('accessibility_password_reset_runtime_unavailable');
      }
    }
  } finally {
    // The password exists only as this unavoidable short-lived JS string; drop the
    // last mutable reference so it becomes collectable as soon as this frame ends.
    password = null;
  }
}

async function main() {
  try {
    const metadata = await resetAccessibilityRunnerPassword(process.env);
    process.stdout.write(`${JSON.stringify(metadata)}\n`);
  } catch (error) {
    // Only a generic allowlisted code may leave this process; never raw error text,
    // SQL, URLs, or any other failure detail.
    let code = 'accessibility_password_reset_failed';
    try {
      code = resolveAccessibilityPasswordResetErrorCode(error);
    } catch {
      // Even code resolution failing keeps the generic allowlisted fallback.
    }
    try {
      process.stderr.write(`${code}\n`);
    } catch {
      // Nothing else can be done; the exit code below still reports failure.
    }
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
