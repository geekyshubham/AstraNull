import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

const CURRENT_PARAMS = Object.freeze({ N: 16_384, r: 8, p: 1 });
const SALT_BYTES = 16;
const HASH_BYTES = 32;
const MAX_PASSWORD_CHARS = 200;
const MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024;

const COMMON_PASSWORDS = new Set([
  '123456789012',
  'admin123456',
  'changeme123!',
  'letmein12345',
  'password123',
  'password123!',
  'qwerty123456',
  'welcome12345',
]);

function scryptMaxmem({ N, r, p }) {
  const required = (128 * N * r) + (128 * r * p) + (256 * r);
  return Math.max(32 * 1024 * 1024, required + (1024 * 1024));
}

function canonicalBase64url(buffer) {
  return buffer.toString('base64url');
}

function decodeCanonicalBase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return canonicalBase64url(decoded) === value ? decoded : null;
  } catch {
    return null;
  }
}

function parseEncodedPassword(encoded) {
  if (typeof encoded !== 'string') return null;
  const match = encoded.match(
    /^scrypt\$N=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/,
  );
  if (!match) return null;

  const params = {
    N: Number(match[1]),
    r: Number(match[2]),
    p: Number(match[3]),
  };
  if (
    !Number.isSafeInteger(params.N)
    || !Number.isSafeInteger(params.r)
    || !Number.isSafeInteger(params.p)
    || params.N < 2
    || (params.N & (params.N - 1)) !== 0
    || params.r < 1
    || params.p < 1
    || params.r > 64
    || params.p > 64
  ) {
    return null;
  }

  const maxmem = scryptMaxmem(params);
  if (maxmem > MAX_SCRYPT_MEMORY_BYTES) return null;

  const salt = decodeCanonicalBase64url(match[4]);
  const expectedHash = decodeCanonicalBase64url(match[5]);
  if (!salt || salt.length < 16 || salt.length > 64 || expectedHash?.length !== HASH_BYTES) {
    return null;
  }
  return { params, salt, expectedHash, maxmem };
}

function assertHashablePassword(plain) {
  if (typeof plain !== 'string') {
    throw new TypeError('password must be a string');
  }
  // This bound is enforced here as well as at the API boundary. A future caller cannot
  // accidentally turn scrypt into an attacker-controlled CPU sink by skipping assessPassword().
  if (plain.length > MAX_PASSWORD_CHARS) {
    throw new RangeError('password exceeds 200 characters');
  }
}

export async function hashPassword(plain) {
  assertHashablePassword(plain);
  const salt = randomBytes(SALT_BYTES);
  const derived = await scrypt(plain, salt, HASH_BYTES, {
    ...CURRENT_PARAMS,
    maxmem: scryptMaxmem(CURRENT_PARAMS),
  });
  return `scrypt$N=${CURRENT_PARAMS.N},r=${CURRENT_PARAMS.r},p=${CURRENT_PARAMS.p}`
    + `$${canonicalBase64url(salt)}$${canonicalBase64url(derived)}`;
}

export async function verifyPassword(plain, encoded) {
  if (typeof plain !== 'string' || plain.length > MAX_PASSWORD_CHARS) return false;
  const parsed = parseEncodedPassword(encoded);
  if (!parsed) return false;
  try {
    const actual = await scrypt(plain, parsed.salt, parsed.expectedHash.length, {
      ...parsed.params,
      maxmem: parsed.maxmem,
    });
    return timingSafeEqual(actual, parsed.expectedHash);
  } catch {
    // Stored credential material is a trust boundary too. Corruption or a hostile encoded cost
    // must produce an ordinary authentication failure, never an exception or process crash.
    return false;
  }
}

export function needsRehash(encoded) {
  const parsed = parseEncodedPassword(encoded);
  if (!parsed) return true;
  return parsed.params.N < CURRENT_PARAMS.N
    || parsed.params.r < CURRENT_PARAMS.r
    || parsed.params.p < CURRENT_PARAMS.p;
}

export function assessPassword(plain, { email } = {}) {
  if (typeof plain !== 'string') {
    return { ok: false, failures: ['invalid_type'] };
  }
  if (plain.length > MAX_PASSWORD_CHARS) {
    // Return immediately: policy evaluation itself must not scan a multi-megabyte password after
    // discovering that it can never be accepted.
    return { ok: false, failures: ['too_long'] };
  }

  const failures = [];
  if (plain.length < 12) failures.push('too_short');

  const classes = [/[a-z]/.test(plain), /[A-Z]/.test(plain), /\d/.test(plain), /[^A-Za-z0-9]/.test(plain)]
    .filter(Boolean).length;
  if (classes < 3) failures.push('insufficient_character_classes');

  const localPart = typeof email === 'string'
    ? email.trim().toLowerCase().split('@', 1)[0]
    : '';
  if (localPart && plain.toLowerCase().includes(localPart)) {
    failures.push('contains_email_local_part');
  }

  if (COMMON_PASSWORDS.has(plain.trim().toLowerCase())) {
    failures.push('common_password');
  }

  return { ok: failures.length === 0, failures };
}
