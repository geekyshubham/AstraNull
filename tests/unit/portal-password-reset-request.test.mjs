import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const source = readFileSync('apps/web/react/src/pages/public-pages.tsx', 'utf8');
const requestStart = source.indexOf('function RequestPasswordResetPage');
const requestEnd = source.indexOf('function ResetPasswordPage', requestStart);
const requestPage = source.slice(requestStart, requestEnd);

describe('portal password recovery initiation', () => {
  it('routes request and token-consumption flows separately', () => {
    assert.match(source, /flow === 'request-password-reset'/);
    assert.match(source, /flow === 'password-reset'/);
    assert.match(source, /RequestPasswordResetPage/);
    assert.match(source, /ResetPasswordPage/);
  });

  it('posts only the trimmed email and displays enumeration-safe success copy', () => {
    assert.match(requestPage, /fetch\('\/v1\/auth\/request-password-reset'/);
    assert.match(requestPage, /JSON\.stringify\(\{ email: email\.trim\(\) \}\)/);
    assert.match(requestPage, /If an account is eligible and recovery delivery is configured and succeeds, instructions may arrive\. This response confirms neither condition\./);
    assert.doesNotMatch(requestPage, /recovery instructions will be sent|instructions will arrive/i);
    assert.doesNotMatch(requestPage, /json\.(?:email|account|delivery)|String\(json\.(?:email|account|delivery)/);
  });

  it('uses a controlled labeled email field and accessible status states', () => {
    assert.match(requestPage, /htmlFor="password-reset-email"/);
    assert.match(requestPage, /id="password-reset-email"[\s\S]*type="email"[\s\S]*value=\{email\}[\s\S]*onChange=/m);
    assert.match(requestPage, /className="success-panel" role="status" aria-live="polite"/);
    assert.match(requestPage, /password_login_disabled[\s\S]*Password recovery is not available on this deployment/m);
  });
});
