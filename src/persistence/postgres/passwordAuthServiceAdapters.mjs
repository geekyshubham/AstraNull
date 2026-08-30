import { createPasswordAuthService } from '../../services/passwordAuth.mjs';

export const PASSWORD_AUTH_REPOSITORY_METHODS = Object.freeze([
  'findUsersByEmail',
  'recordLoginFailure',
  'recordLoginSuccess',
  'completeLogin',
  'findPasswordInviteByTokenHash',
  'setPasswordFromInvite',
  'createPasswordInvite',
  'findCredential',
  'createPasswordReset',
  'findPasswordResetByTokenHash',
  'consumePasswordReset',
  'beginMfaEnrollment',
  'confirmMfaEnrollment',
  'disableMfa',
]);

export const POSTGRES_PASSWORD_AUTH_SERVICE_METHODS = Object.freeze([
  'loginWithPassword',
  'setPasswordWithInvite',
  'issuePasswordInvite',
  'requestPasswordReset',
  'resetPasswordWithToken',
  'beginMfaEnrollment',
  'confirmMfaEnrollment',
  'disableMfa',
  'validatePasswordSession',
]);

export function createPostgresPasswordAuthServices(repositories) {
  const passwordAuth = repositories?.passwordAuth;
  if (!passwordAuth || typeof passwordAuth !== 'object') {
    throw new Error('Postgres password auth service adapter requires repositories.passwordAuth.');
  }
  for (const method of PASSWORD_AUTH_REPOSITORY_METHODS) {
    if (typeof passwordAuth[method] !== 'function') {
      throw new Error(`Postgres password auth service adapter requires passwordAuth.${method}().`);
    }
  }
  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres password auth service adapter requires audit.appendAuditEvent().');
  }
  return createPasswordAuthService({ ...passwordAuth, auditService: audit });
}
