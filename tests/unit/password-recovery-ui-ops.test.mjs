import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { buildPasswordRecoveryEmail } from '../../src/persistence/postgres/passwordRecoveryDelivery.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relativePath) => readFileSync(path.join(ROOT, relativePath), 'utf8');

describe('password recovery portal contract', () => {
  it('links recovery email to a real public route and keeps invitation activation separate', () => {
    const email = buildPasswordRecoveryEmail({
      email: 'owner@example.test',
      reset_token: 'pwr_secret&value',
      expires_at: '2026-08-30T02:00:00.000Z',
    }, {
      ASTRANULL_PUBLIC_BASE_URL: 'https://astranull.example.test',
      ASTRANULL_SMTP_FROM: 'noreply@astranull.example.test',
    });
    const match = email.html_body.match(/href="([^"]+)"/);
    assert.ok(match);
    const resetUrl = new URL(match[1].replaceAll('&amp;', '&'));
    assert.equal(resetUrl.pathname, '/login');
    assert.equal(resetUrl.searchParams.get('flow'), 'password-reset');
    assert.equal(resetUrl.searchParams.get('token'), 'pwr_secret&value');

    const appSource = read('apps/web/react/src/App.tsx');
    assert.match(appSource, /path === '\/login'/);
    const publicPages = read('apps/web/react/src/pages/public-pages.tsx');
    assert.match(publicPages, /function ResetPasswordPage[\s\S]*fetch\('\/v1\/auth\/reset-password'/);
    assert.match(publicPages, /export function SetPasswordPage[\s\S]*fetch\('\/v1\/auth\/set-password'/);
  });

  it('progressively submits a six-digit TOTP only after mfa_required', () => {
    const publicPages = read('apps/web/react/src/pages/public-pages.tsx');
    assert.match(publicPages, /code === 'mfa_required' \|\| code === 'mfa_invalid'/);
    assert.match(publicPages, /if \(mfaRequired\) body\.totp = totp\.trim\(\)/);
    assert.match(publicPages, /id="login-totp"[\s\S]*autoComplete="one-time-code"[\s\S]*pattern="\[0-9\]\{6\}"/);
    assert.doesNotMatch(publicPages, /request-password-reset[\s\S]*account_exists/);
  });
});

describe('password recovery Compose contract', () => {
  it('is always on, restart-safe, and never borrows probe tenant scope', () => {
    const compose = read('ops/aws/docker-compose.yml');
    const worker = compose.split('  password-recovery-worker:')[1].split('\n  caddy:')[0];
    assert.doesNotMatch(worker, /profiles:/);
    assert.match(worker, /restart: unless-stopped/);
    assert.doesNotMatch(worker, /ASTRANULL_PROBE_TENANT_ID|--tenant-id/);

    const envExample = read('ops/aws/env.example');
    assert.match(envExample, /ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS=ten_demo/);
    assert.match(envExample, /ASTRANULL_PASSWORD_RECOVERY_INTERVAL_MS=5000/);
  });
});
