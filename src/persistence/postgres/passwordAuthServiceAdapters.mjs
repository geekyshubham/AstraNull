import { createPasswordAuthService } from '../../services/passwordAuth.mjs';

export const PASSWORD_AUTH_REPOSITORY_METHODS = Object.freeze([
  'findUsersByEmail',
  'recordLoginFailure',
  'recordLoginSuccess',
  'findPasswordInviteByTokenHash',
  'setPasswordFromInvite',
  'createPasswordInvite',
]);

export const POSTGRES_PASSWORD_AUTH_SERVICE_METHODS = Object.freeze([
  'loginWithPassword',
  'setPasswordWithInvite',
  'issuePasswordInvite',
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
