import assert from 'node:assert/strict';
import {
  createHmac,
  createSign,
  generateKeyPairSync,
} from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import http from 'node:http';
import {
  clearJwksCache,
  verifyOidcBearerToken,
  verifyOidcStaffBearerToken,
} from '../../src/lib/oidc.mjs';

const ISSUER = 'https://idp.test.example';
const AUDIENCE = 'astranull-api';
const KID = 'staff-rsa-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
// Second, untrusted pair: used to prove the signature is actually verified and
// that a matching `kid` alone never buys trust.
const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 });

const publicJwk = publicKey.export({ format: 'jwk' });
publicJwk.kid = KID;
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function signRs256Jwt(payload, headerExtra = {}, key = privateKey) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID, ...headerExtra };
  const headerB64 = base64UrlJson(header);
  const payloadB64 = base64UrlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(key);
  return `${signingInput}.${sig.toString('base64url')}`;
}

/** Unsigned `alg:none` token with an empty signature segment. */
function signNoneAlgJwt(payload) {
  const headerB64 = base64UrlJson({ alg: 'none', typ: 'JWT', kid: KID });
  const payloadB64 = base64UrlJson(payload);
  return `${headerB64}.${payloadB64}.`;
}

/** HS256/RS256 confusion: HMAC the token using the RSA public key as the secret. */
function signHs256WithPublicKeyAsSecret(payload) {
  const headerB64 = base64UrlJson({ alg: 'HS256', typ: 'JWT', kid: KID });
  const payloadB64 = base64UrlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const secret = publicKey.export({ type: 'spki', format: 'pem' });
  const sig = createHmac('sha256', secret).update(signingInput, 'utf8').digest('base64url');
  return `${signingInput}.${sig}`;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function staffOidcConfig(jwksUrl, overrides = {}) {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUrl,
    tenantClaim: 'tenant_id',
    roleClaim: 'role',
    userClaim: 'sub',
    staffRoleClaim: 'staff_role',
    requireMfa: false,
    mfaClaim: 'amr',
    mfaValues: ['mfa', 'otp', 'webauthn', 'fido', 'fido2', 'phishing_resistant'],
    jwksCacheTtlMs: 300_000,
    rolePrefix: null,
    roleMap: {},
    // Explicit empty staff map keeps tests isolated from ambient env config.
    staffRoleMap: {},
    requireExplicitRoleMap: false,
    ...overrides,
  };
}

function startJwksServer(keys) {
  const server = http.createServer((req, res) => {
    if (req.url === '/jwks' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, jwksUrl: `http://127.0.0.1:${port}/jwks` });
    });
  });
}

/** Run `fn` against a JWKS server serving the trusted key, then close it. */
async function withJwks(fn, keys = [publicJwk]) {
  const { server, jwksUrl } = await startJwksServer(keys);
  try {
    return await fn(jwksUrl);
  } finally {
    server.close();
  }
}

afterEach(() => {
  clearJwksCache();
});

describe('verifyOidcStaffBearerToken — staff role map enforcement', () => {
  it('rejects a self-asserted unmapped staff role when requireExplicitRoleMap is enabled', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        staffRoleMap: { 'corp-security-admin': 'security_admin' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_evil',
        staff_role: 'security_admin',
        exp: nowSec() + 3600,
      });
      assert.deepEqual(
        await verifyOidcStaffBearerToken(token, cfg),
        { error: 'invalid_staff_role' },
      );
    });
  });

  it('rejects a self-asserted unmapped internal_admin claim when requireExplicitRoleMap is enabled', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        staffRoleMap: { 'corp-admins': 'internal_admin' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_evil',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal(
        (await verifyOidcStaffBearerToken(token, cfg)).error,
        'invalid_staff_role',
      );
    });
  });

  it('accepts an explicitly mapped staff role value under requireExplicitRoleMap', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        staffRoleMap: { 'corp-security-admin': 'security_admin' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_ok',
        staff_role: 'corp-security-admin',
        exp: nowSec() + 3600,
      });
      const ctx = await verifyOidcStaffBearerToken(token, cfg);
      assert.equal(ctx.error, undefined);
      assert.equal(ctx.staffRole, 'security_admin');
      assert.equal(ctx.staffId, 'staff_ok');
    });
  });

  it('resolves mapped staff roles from an array staff_role claim', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        staffRoleMap: { 'corp-soc-lead': 'soc_lead' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_arr',
        staff_role: ['unrelated-group', 'corp-soc-lead'],
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).staffRole, 'soc_lead');
    });
  });

  it('does not let the customer roleMap mint staff privileges', async () => {
    await withJwks(async (jwksUrl) => {
      // The customer map would resolve corp-admin -> internal_admin. The staff
      // path must consult only the staff map, so this stays unmapped.
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        roleMap: { 'corp-admin': 'internal_admin' },
        staffRoleMap: {},
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_crossover',
        staff_role: 'corp-admin',
        exp: nowSec() + 3600,
      });
      assert.equal(
        (await verifyOidcStaffBearerToken(token, cfg)).error,
        'invalid_staff_role',
      );
    });
  });

  it('reads the staff role map from ASTRANULL_OIDC_STAFF_ROLE_MAP when not configured inline', async () => {
    await withJwks(async (jwksUrl) => {
      process.env.ASTRANULL_OIDC_STAFF_ROLE_MAP = 'corp-billing:billing_ops';
      try {
        const cfg = staffOidcConfig(jwksUrl, {
          requireExplicitRoleMap: true,
          staffRoleMap: undefined,
        });
        const mapped = signRs256Jwt({
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'staff_env',
          staff_role: 'corp-billing',
          exp: nowSec() + 3600,
        });
        assert.equal((await verifyOidcStaffBearerToken(mapped, cfg)).staffRole, 'billing_ops');

        const unmapped = signRs256Jwt({
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'staff_env',
          staff_role: 'billing_ops',
          exp: nowSec() + 3600,
        });
        assert.equal(
          (await verifyOidcStaffBearerToken(unmapped, cfg)).error,
          'invalid_staff_role',
        );
      } finally {
        delete process.env.ASTRANULL_OIDC_STAFF_ROLE_MAP;
      }
    });
  });

  it('rejects a mapped value that is not a known staff role', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        staffRoleMap: { 'corp-admin': 'admin' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_customer_role',
        staff_role: 'corp-admin',
        exp: nowSec() + 3600,
      });
      assert.equal(
        (await verifyOidcStaffBearerToken(token, cfg)).error,
        'invalid_staff_role',
      );
    });
  });
});

describe('verifyOidcStaffBearerToken — staff claim isolation from customer roles', () => {
  it('does not grant staff access from the customer role claim alone', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_customer',
        tenant_id: 'ten_demo',
        role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.deepEqual(
        await verifyOidcStaffBearerToken(token, cfg),
        { error: 'invalid_staff_role' },
      );
    });
  });

  it('does not grant staff access from a customer-mapped role claim', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        roleClaim: 'groups',
        roleMap: { 'corp-admin': 'internal_admin' },
      });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_customer',
        tenant_id: 'ten_demo',
        groups: ['corp-admin'],
        exp: nowSec() + 3600,
      });
      assert.equal(
        (await verifyOidcStaffBearerToken(token, cfg)).error,
        'invalid_staff_role',
      );
    });
  });

  it('accepts staff_role when the customer role claim is absent', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_admin',
        staff_role: 'soc_analyst',
        exp: nowSec() + 3600,
      });
      const ctx = await verifyOidcStaffBearerToken(token, cfg);
      assert.deepEqual(ctx, {
        principalType: 'staff',
        staffId: 'staff_admin',
        staffRole: 'soc_analyst',
        userId: 'staff_admin',
        role: 'soc_analyst',
        tenantId: null,
      });
    });
  });

  it('accepts an unmapped staff_role when requireExplicitRoleMap is disabled (non-production only)', async () => {
    await withJwks(async (jwksUrl) => {
      // requireExplicitRoleMap=false with no staff role map: raw claims resolve.
      //
      // This is NOT the deployed shape any more. Production enables the flag regardless of
      // deployment profile, so a hosted-staging deployment refuses exactly this token — that
      // refusal is what retires the staff bearers minted before the bundled staff-login mint was
      // closed. What remains covered here is local/dev and E2E, where the flag stays off.
      const cfg = staffOidcConfig(jwksUrl, { requireExplicitRoleMap: false });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_admin',
        tenant_id: 'ten_demo',
        role: 'internal_admin',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      const ctx = await verifyOidcStaffBearerToken(token, cfg);
      assert.equal(ctx.error, undefined);
      assert.equal(ctx.staffRole, 'internal_admin');
      assert.equal(ctx.principalType, 'staff');
      assert.equal(ctx.tenantId, 'ten_demo');
    });
  });

  it('supports a custom staff role claim name', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, { staffRoleClaim: 'astranull.staff' });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_nested',
        astranull: { staff: 'support_engineer' },
        exp: nowSec() + 3600,
      });
      assert.equal(
        (await verifyOidcStaffBearerToken(token, cfg)).staffRole,
        'support_engineer',
      );
    });
  });

  it('rejects a staff token with no usable subject claim', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });
});

describe('verifyOidcStaffBearerToken — not-before enforcement', () => {
  it('rejects a not-yet-valid token as invalid_token', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_future',
        staff_role: 'internal_admin',
        nbf: nowSec() + 99_999,
        exp: nowSec() + 200_000,
      });
      assert.deepEqual(
        await verifyOidcStaffBearerToken(token, cfg),
        { error: 'invalid_token' },
      );
    });
  });

  it('rejects a non-numeric nbf', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_bad_nbf',
        staff_role: 'internal_admin',
        nbf: 'later',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('accepts an nbf inside the clock tolerance window', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_now',
        staff_role: 'internal_admin',
        nbf: nowSec() + 30,
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).staffRole, 'internal_admin');
    });
  });
});

describe('verifyOidcStaffBearerToken — JWT hardening', () => {
  it('rejects a token signed by an untrusted key reusing a trusted kid', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt(
        {
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'staff_forged',
          staff_role: 'internal_admin',
          exp: nowSec() + 3600,
        },
        {},
        attacker.privateKey,
      );
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects a token whose payload was tampered with after signing', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_low',
        staff_role: 'support_engineer',
        exp: nowSec() + 3600,
      });
      const [headerB64, , sigB64] = token.split('.');
      const escalated = base64UrlJson({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_low',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      const tampered = `${headerB64}.${escalated}.${sigB64}`;
      assert.equal((await verifyOidcStaffBearerToken(tampered, cfg)).error, 'invalid_token');
    });
  });

  it('rejects alg:none', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signNoneAlgJwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_none',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects HS256 signed with the RSA public key as the shared secret', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signHs256WithPublicKeyAsSecret({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_confused',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects a missing kid header', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt(
        {
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'staff_nokid',
          staff_role: 'internal_admin',
          exp: nowSec() + 3600,
        },
        { kid: undefined },
      );
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects an unknown kid', async () => {
    await withJwks(
      async (jwksUrl) => {
        const cfg = staffOidcConfig(jwksUrl);
        const token = signRs256Jwt({
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'staff_kid',
          staff_role: 'internal_admin',
          exp: nowSec() + 3600,
        });
        assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
      },
      [{ ...publicJwk, kid: 'some-other-kid' }],
    );
  });

  it('rejects a wrong issuer', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: 'https://evil.example',
        aud: AUDIENCE,
        sub: 'staff_iss',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects a wrong audience', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: 'some-other-api',
        sub: 'staff_aud',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'invalid_token');
    });
  });

  it('rejects expired tokens and non-numeric exp', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const expired = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_exp',
        staff_role: 'internal_admin',
        exp: nowSec() - 120,
      });
      assert.equal((await verifyOidcStaffBearerToken(expired, cfg)).error, 'expired');

      const missing = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_exp',
        staff_role: 'internal_admin',
      });
      assert.equal((await verifyOidcStaffBearerToken(missing, cfg)).error, 'expired');

      const bogus = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_exp',
        staff_role: 'internal_admin',
        exp: String(nowSec() + 3600),
      });
      assert.equal((await verifyOidcStaffBearerToken(bogus, cfg)).error, 'invalid_token');
    });
  });

  it('rejects a malformed token', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      assert.equal((await verifyOidcStaffBearerToken('not-a-jwt', cfg)).error, 'invalid_token');
      assert.equal((await verifyOidcStaffBearerToken('', cfg)).error, 'invalid_token');
    });
  });

  it('enforces MFA on the staff path', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, { requireMfa: true });
      const noMfa = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_mfa',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(noMfa, cfg)).error, 'mfa_required');

      const withMfa = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_mfa',
        staff_role: 'internal_admin',
        amr: ['pwd', 'webauthn'],
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcStaffBearerToken(withMfa, cfg)).staffRole, 'internal_admin');
    });
  });
});

describe('OIDC verifier envelope parity', () => {
  // Guards the root cause: both verifiers must run the identical envelope
  // gauntlet, so an envelope check can never regress on only one path.
  const envelopeCases = () => {
    const base = {
      iss: ISSUER,
      aud: AUDIENCE,
      sub: 'usr_parity',
      tenant_id: 'ten_parity',
      role: 'admin',
      staff_role: 'internal_admin',
      exp: nowSec() + 3600,
    };
    return [
      ['malformed token', 'nope', 'invalid_token'],
      ['alg none', signNoneAlgJwt(base), 'invalid_token'],
      ['HS256 confusion', signHs256WithPublicKeyAsSecret(base), 'invalid_token'],
      ['untrusted signing key', signRs256Jwt(base, {}, attacker.privateKey), 'invalid_token'],
      ['missing kid', signRs256Jwt(base, { kid: undefined }), 'invalid_token'],
      ['wrong issuer', signRs256Jwt({ ...base, iss: 'https://evil.example' }), 'invalid_token'],
      ['wrong audience', signRs256Jwt({ ...base, aud: 'nope' }), 'invalid_token'],
      ['expired', signRs256Jwt({ ...base, exp: nowSec() - 300 }), 'expired'],
      ['non-numeric exp', signRs256Jwt({ ...base, exp: 'soon' }), 'invalid_token'],
      ['future nbf', signRs256Jwt({ ...base, nbf: nowSec() + 99_999 }), 'invalid_token'],
      ['non-numeric nbf', signRs256Jwt({ ...base, nbf: 'later' }), 'invalid_token'],
    ];
  };

  it('returns identical envelope errors from the customer and staff verifiers', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      for (const [name, token, expected] of envelopeCases()) {
        const customer = await verifyOidcBearerToken(token, cfg);
        const staff = await verifyOidcStaffBearerToken(token, cfg);
        assert.equal(customer.error, expected, `customer path: ${name}`);
        assert.equal(staff.error, expected, `staff path: ${name}`);
      }
    });
  });

  it('rejects the same envelope failures when MFA is required on both paths', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, { requireMfa: true });
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_parity',
        tenant_id: 'ten_parity',
        role: 'admin',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, cfg)).error, 'mfa_required');
      assert.equal((await verifyOidcStaffBearerToken(token, cfg)).error, 'mfa_required');
    });
  });
});

describe('verifyOidcBearerToken — customer path regression', () => {
  it('still verifies a valid customer token and maps claims', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_regression',
        tenant_id: 'ten_regression',
        role: 'engineer',
        exp: nowSec() + 3600,
      });
      assert.deepEqual(await verifyOidcBearerToken(token, cfg), {
        tenantId: 'ten_regression',
        userId: 'usr_regression',
        role: 'engineer',
      });
    });
  });

  it('still enforces requireExplicitRoleMap on the customer path', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl, {
        requireExplicitRoleMap: true,
        roleMap: { 'corp-admin': 'admin' },
      });
      const unmapped = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_strict',
        tenant_id: 'ten_strict',
        role: 'admin',
        exp: nowSec() + 3600,
      });
      assert.deepEqual(await verifyOidcBearerToken(unmapped, cfg), { error: 'invalid_role' });

      const mapped = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_strict',
        tenant_id: 'ten_strict',
        role: 'corp-admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcBearerToken(mapped, cfg)).role, 'admin');
    });
  });

  it('still requires tenant and user claims and a known role', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const noTenant = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        role: 'admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcBearerToken(noTenant, cfg)).error, 'invalid_token');

      const unknownRole = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'superuser',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcBearerToken(unknownRole, cfg)).error, 'invalid_role');
    });
  });

  it('does not grant a customer role from the staff_role claim', async () => {
    await withJwks(async (jwksUrl) => {
      const cfg = staffOidcConfig(jwksUrl);
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'staff_only',
        tenant_id: 'ten_demo',
        staff_role: 'internal_admin',
        exp: nowSec() + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, cfg)).error, 'invalid_role');
    });
  });
});
