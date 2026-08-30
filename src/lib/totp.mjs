/**
 * RFC 6238 TOTP (SHA-1, 30-second step, 6 digits) with base32 secret handling.
 *
 * Dependency-free BE-019 MFA primitive for conditional access on password logins.
 * Secrets are generated with node:crypto randomBytes and rendered as otpauth:// URIs
 * for authenticator apps; no QR dependency is shipped.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_DEFAULT_WINDOW = 1;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** @param {Uint8Array} bytes */
export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** @param {string} input base32 (A-Z, 2-7); whitespace and '=' padding tolerated */
export function base32Decode(input) {
  const clean = String(input ?? '').toUpperCase().replace(/[\s=]/g, '');
  if (!clean.length || /[^A-Z2-7]/.test(clean)) return null;
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Generates a fresh 160-bit TOTP secret, base32-encoded. */
export function generateTotpSecret() {
  return base32Encode(randomBytes(20));
}

function hotp(secretBytes, counter) {
  if (!Number.isSafeInteger(counter) || counter < 0) return null;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secretBytes).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (
    ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3]
  ) % 10 ** TOTP_DIGITS;
  return String(code).padStart(TOTP_DIGITS, '0');
}

/**
 * Verify a TOTP for the current time (± window steps). Every candidate in the bounded
 * acceptance window is compared before returning so the matching drift is not exposed by
 * an early-return timing difference.
 *
 * @param {string} secret base32 TOTP secret
 * @param {string} token 6-digit code
 * @param {{ now?: Date|number, window?: number, stepSeconds?: number }} [options]
 * @returns {{ ok: boolean, matchedStep?: number }}
 */
export function verifyTotp(secret, token, options = {}) {
  const normalized = String(token ?? '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return { ok: false };
  const secretBytes = base32Decode(secret);
  if (!secretBytes || secretBytes.length === 0) return { ok: false };

  const stepSeconds = Number(options.stepSeconds ?? TOTP_STEP_SECONDS);
  const nowMs = options.now instanceof Date ? options.now.getTime() : Number(options.now ?? Date.now());
  const requestedWindow = Number(options.window ?? TOTP_DEFAULT_WINDOW);
  if (!Number.isFinite(nowMs) || !Number.isSafeInteger(stepSeconds) || stepSeconds < 1) {
    return { ok: false };
  }
  const window = Number.isFinite(requestedWindow)
    ? Math.max(0, Math.min(5, Math.floor(requestedWindow)))
    : TOTP_DEFAULT_WINDOW;
  const currentStep = Math.floor(nowMs / 1000 / stepSeconds);
  if (!Number.isSafeInteger(currentStep) || currentStep < 0) return { ok: false };

  const presented = Buffer.from(normalized, 'ascii');
  let matchedStep;
  for (let drift = -window; drift <= window; drift += 1) {
    const step = currentStep + drift;
    const candidate = hotp(secretBytes, step);
    const expected = Buffer.from(candidate ?? '000000', 'ascii');
    if (timingSafeEqual(expected, presented) && candidate !== null && matchedStep === undefined) {
      matchedStep = step;
    }
  }
  return matchedStep === undefined ? { ok: false } : { ok: true, matchedStep };
}

/** otpauth:// provisioning URI for authenticator apps (no QR rendering). */
export function buildOtpauthUri({ secret, accountLabel, issuer = 'AstraNull' }) {
  const label = encodeURIComponent(`${issuer}:${String(accountLabel ?? 'user')}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Deterministic code for a specific step counter, used by focused tests. */
export function computeTotpAtStep(secret, step) {
  const secretBytes = base32Decode(secret);
  if (!secretBytes || secretBytes.length === 0) return null;
  return hotp(secretBytes, step);
}
