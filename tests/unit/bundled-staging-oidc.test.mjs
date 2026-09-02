import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  getBundledStagingJwksDocument,
  assertBundledStagingOidcFixtureUsable,
  mintBundledStagingOidcJwt,
  resetBundledStagingOidcFixtureCache,
  resolveBundledStagingOidcIssuer,
  resolvePublicBaseUrl,
} from '../../src/lib/bundledStagingOidc.mjs';
import { resolveDeploymentProfile } from '../../src/lib/deploymentProfile.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';

const TEST_SECRET_ENCRYPTION_KEY = randomBytes(32).toString('hex');
const TEST_PROBE_WORKER_SECRET = randomBytes(32).toString('base64url');

/**
 * RSA modulus of the fixture key that was committed to this public repo until 2026-08-01.
 * This is *public* key material, deliberately checked in so the burned-key refusal is pinned
 * by test. The matching private key is not here and must never be: it is compromised, and the
 * loader identifies it from the modulus alone.
 */
const BURNED_PUBLIC_MODULUS =
  '1UENnx9uBPoE90O3iuKHxCZiGf6a85UY_DkodYzHzADQmid12KCtiIRa1Iy_K4z3ybWvP6k7L21FllHqUh2JIFU'
  + 'WQLDaMEptnYwv-w1pmi4DXnl9CXDm0P8M-_hf3D-cBsip_4y3GCwGlQzkjKEK5uQuKzq1WBTk0pAxg12kpffv9'
  + 'LousfVMBBqSF5joThmCht05CPRaZEnG8rLfwNk9-haoy6ROtlDWhYnpcDpNkAvMV6CuuknTwMAXpQBwsgpLppa'
  + 's7LhK9aNSnOnEf1S-vLgaOVHdf2kFHjJleY-LaZ0UffEjI1Ebhu_mUDr8MYFwEduGny1HPeQVa4lHs6-ITQ';

/** A throwaway, never-published fixture — regenerated per call so no key is shared across tests. */
function freshFixture({ modulusLength = 2048, kid = 'test-rsa-1' } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
  const publicJwk = publicKey.export({ format: 'jwk' });
  publicJwk.kid = kid;
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  return {
    issuer_suffix: '/staging-oidc',
    audience: 'astranull-hosted-staging',
    kid,
    public_jwk: publicJwk,
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function fixtureEnv(fixture) {
  return {
    ASTRANULL_BUNDLED_STAGING_OIDC: '1',
    ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
    ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON:
      typeof fixture === 'string' ? fixture : JSON.stringify(fixture),
  };
}

function assertStartupRejects(fixture, extraSecretNeedles = []) {
  resetBundledStagingOidcFixtureCache();
  let captured;
  assert.throws(
    () => assertBundledStagingOidcFixtureUsable(fixtureEnv(fixture)),
    (error) => {
      captured = error;
      return true;
    },
  );
  const needles = [
    fixture?.private_key_pem,
    fixture?.public_jwk?.n,
    fixture?.public_jwk?.d,
    ...extraSecretNeedles,
  ].filter((value) => typeof value === 'string' && value.length >= 8);
  for (const needle of needles) {
    assert.equal(captured.message.includes(needle), false, 'error must not echo key material');
  }
  return captured.message;
}

describe('bundled staging OIDC', () => {
  it('mints JWT and exposes JWKS document', () => {
    const env = {
      ASTRANULL_BUNDLED_STAGING_OIDC: '1',
      ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
    };
    const jwks = getBundledStagingJwksDocument(env);
    assert.equal(Array.isArray(jwks.keys), true);
    assert.equal(jwks.keys.length, 1);
    const token = mintBundledStagingOidcJwt({ role: 'admin', tenantId: 'ten_demo', userId: 'usr_admin' }, env);
    assert.match(token, /^eyJ/);
    assert.match(resolveBundledStagingOidcIssuer(env), /^https:\/\/staging\.example\.test\/staging-oidc$/);
  });

  it('resolvePublicBaseUrl prefers explicit and platform URLs', () => {
    assert.equal(
      resolvePublicBaseUrl({ ASTRANULL_PUBLIC_BASE_URL: 'https://astranull.site' }),
      'https://astranull.site',
    );
    assert.equal(
      resolvePublicBaseUrl({ APP_URL: 'https://astranull.site/' }),
      'https://astranull.site',
    );
  });

  it('maps bundled OIDC flag to hosted-staging deployment profile', () => {
    assert.equal(resolveDeploymentProfile({ ASTRANULL_BUNDLED_STAGING_OIDC: '1' }), 'hosted-staging');
  });

  it('mints from a fixture supplied inline via the environment', () => {
    // How deployments inject the key: the file is gitignored and excluded from the image,
    // so there is nothing on disk to read.
    resetBundledStagingOidcFixtureCache();
    const token = mintBundledStagingOidcJwt(
      { role: 'admin' },
      {
        ASTRANULL_BUNDLED_STAGING_OIDC: '1',
        ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
        ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON: JSON.stringify(freshFixture()),
      },
    );
    assert.match(token, /^eyJ/);
  });

  it('startup rejects malformed PEM and non-RSA private keys without crypto details', () => {
    const malformed = freshFixture();
    malformed.private_key_pem = 'TOP-SECRET-MALFORMED-PEM-MARKER';
    const malformedMessage = assertStartupRejects(malformed, [malformed.private_key_pem]);
    assert.match(malformedMessage, /invalid private signing key/);
    assert.doesNotMatch(malformedMessage, /decoder|openssl|asn1/i);

    const nonRsa = freshFixture();
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    nonRsa.private_key_pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    assert.match(assertStartupRejects(nonRsa), /RSA private signing key/);
  });

  it('startup rejects RSA-1024 even when its public JWK matches', () => {
    const weak = freshFixture({ modulusLength: 1024 });
    assert.match(assertStartupRejects(weak), /at least 2048 bits/);
  });

  it('startup rejects bad JWK kty, alg, use, kid, canonical n/e, and private fields', () => {
    const cases = [
      ['kty', (fixture) => { fixture.public_jwk.kty = 'EC'; }, /kty=RSA/],
      ['alg', (fixture) => { fixture.public_jwk.alg = 'RS512'; }, /alg=RS256/],
      ['use', (fixture) => { fixture.public_jwk.use = 'enc'; }, /use=sig/],
      ['kid', (fixture) => {
        fixture.kid = 'short';
        fixture.public_jwk.kid = 'short';
      }, /bounded public signing key id/],
      ['n', (fixture) => { fixture.public_jwk.n = `${fixture.public_jwk.n}=`; }, /canonical base64url/],
      ['e', (fixture) => { fixture.public_jwk.e = 'AAQAB'; }, /canonical base64url/],
      ['private', (fixture) => {
        fixture.public_jwk.d = 'PRIVATE-JWK-MATERIAL-MUST-NOT-LEAK';
      }, /must not contain private key fields/],
    ];
    for (const [label, mutate, expected] of cases) {
      const fixture = freshFixture();
      mutate(fixture);
      const message = assertStartupRejects(fixture);
      assert.match(message, expected, label);
    }
  });

  it('startup rejects kid mismatch and public n/e that do not match the private key', () => {
    const kidMismatch = freshFixture();
    kidMismatch.kid = 'different-rsa-kid';
    assert.match(assertStartupRejects(kidMismatch), /kid does not match/);

    const keyMismatch = freshFixture();
    const other = freshFixture();
    keyMismatch.public_jwk.n = other.public_jwk.n;
    keyMismatch.public_jwk.e = other.public_jwk.e;
    assert.match(assertStartupRejects(keyMismatch), /does not match private_key_pem/);
  });

  it('inline cache key includes fixture content and cannot reuse a prior valid fixture', () => {
    resetBundledStagingOidcFixtureCache();
    const valid = freshFixture();
    assert.doesNotThrow(() => assertBundledStagingOidcFixtureUsable(fixtureEnv(valid)));

    const malformed = { ...valid, public_jwk: { ...valid.public_jwk, alg: 'RS512' } };
    assert.throws(
      () => assertBundledStagingOidcFixtureUsable(fixtureEnv(malformed)),
      /alg=RS256/,
    );
  });

  it('refuses the signing key that was published in this repository', () => {
    // Identification is by public modulus, so this needs no compromised private key: a fresh
    // keypair carrying the published modulus is enough to prove the check fires. That is also
    // the realistic failure mode — an old checkout or stale image layer redeploying that key.
    const burned = { ...freshFixture(), public_jwk: { ...freshFixture().public_jwk, n: BURNED_PUBLIC_MODULUS } };
    resetBundledStagingOidcFixtureCache();
    assert.throws(
      () => getBundledStagingJwksDocument({
        ASTRANULL_BUNDLED_STAGING_OIDC: '1',
        ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
        ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE_JSON: JSON.stringify(burned),
      }),
      /published in this repository/,
    );
    resetBundledStagingOidcFixtureCache();
  });

  it('explains how to supply a missing fixture instead of leaking ENOENT', () => {
    resetBundledStagingOidcFixtureCache();
    assert.throws(
      () => getBundledStagingJwksDocument({
        ASTRANULL_BUNDLED_STAGING_OIDC: '1',
        ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
        ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE: '/nonexistent/bundled-oidc-fixture.json',
      }),
      (err) => /oidc:fixture:generate/.test(err.message) && !/ENOENT/.test(err.message),
    );
  });

  it('allows bearer agent identity for hosted-staging in production NODE_ENV', () => {
    const config = loadRuntimeConfig({
      NODE_ENV: 'production',
      ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
      ASTRANULL_BUNDLED_STAGING_OIDC: '1',
      ASTRANULL_DATABASE_URL: 'postgresql://user:pass@localhost:5432/astranull',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_AUTH_MODE: 'oidc-jwt',
      ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: TEST_PROBE_WORKER_SECRET,
      ASTRANULL_AGENT_IDENTITY_MODE: 'bearer',
      ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled',
      ASTRANULL_SECRET_ENCRYPTION_KEY: TEST_SECRET_ENCRYPTION_KEY,
    });
    assert.equal(config.deploymentProfile, 'hosted-staging');
    assert.equal(config.agentIdentityMode, 'bearer');
    assert.equal(config.authMode, 'oidc-jwt');
  });

  /**
   * A half-finished IdP cutover is a fail-OPEN, and nothing used to stop it booting.
   *
   * The bundled mint route stamps tokens with whatever ASTRANULL_OIDC_ISSUER/_AUDIENCE resolve
   * to — it does not pin them to the fixture's own identity. Verification separately follows
   * ASTRANULL_OIDC_JWKS_URL, which falls back to this app's own /.well-known/jwks.json, i.e.
   * the fixture's public key. Set the first two at a real IdP and forget the third and an
   * UNAUTHENTICATED route mints tokens carrying the real IdP's `iss`, signed by our fixture
   * key, which the app then accepts: anonymous impersonation of the corporate IdP.
   */
  describe('bundled fixture vs real IdP contradiction', () => {
    const DO_HOST = 'https://astranull-qteog.ondigitalocean.app';

    /** The live App Platform env, minus the OIDC variables under test. */
    const productionEnv = (extra) => ({
      NODE_ENV: 'production',
      ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
      ASTRANULL_DATABASE_URL: 'postgresql://user:pass@localhost:5432/astranull',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_AUTH_MODE: 'oidc-jwt',
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: TEST_PROBE_WORKER_SECRET,
      ASTRANULL_AGENT_IDENTITY_MODE: 'bearer',
      ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled',
      ASTRANULL_SECRET_ENCRYPTION_KEY:
        TEST_SECRET_ENCRYPTION_KEY,
      ...extra,
    });

    it('boots the live .do/app.yaml shape, where all three OIDC vars are set explicitly', () => {
      // The check must not be "issuer must be unset": both specs DO set it, pointing at this
      // app's own endpoints. Requiring it unset would refuse the running configuration.
      const config = loadRuntimeConfig(productionEnv({
        ASTRANULL_BUNDLED_STAGING_OIDC: '1',
        ASTRANULL_PUBLIC_BASE_URL: DO_HOST,
        ASTRANULL_OIDC_ISSUER: `${DO_HOST}/staging-oidc`,
        ASTRANULL_OIDC_JWKS_URL: `${DO_HOST}/.well-known/jwks.json`,
        ASTRANULL_OIDC_AUDIENCE: 'astranull-hosted-staging',
      }));
      assert.equal(config.bundledStagingOidc, true);
    });

    it('boots when the issuer origin differs from the public base URL', () => {
      // ops/digitalocean/app.yaml serves astranull.site while its issuer names the
      // ondigitalocean.app hostname of the same app. So the invariant cannot be
      // "issuer must match ASTRANULL_PUBLIC_BASE_URL" — only that the issuer and the key
      // which validates it belong together.
      const config = loadRuntimeConfig(productionEnv({
        ASTRANULL_BUNDLED_STAGING_OIDC: '1',
        ASTRANULL_PUBLIC_BASE_URL: 'https://astranull.site',
        ASTRANULL_OIDC_ISSUER: `${DO_HOST}/staging-oidc`,
        ASTRANULL_OIDC_JWKS_URL: `${DO_HOST}/.well-known/jwks.json`,
        ASTRANULL_OIDC_AUDIENCE: 'astranull-hosted-staging',
      }));
      assert.equal(config.bundledStagingOidc, true);
    });

    it('refuses to start when the issuer is a real IdP but JWKS_URL was forgotten', () => {
      // The dangerous shape. JWKS falls back to our own host, so fixture-signed tokens
      // bearing the real IdP's issuer would verify.
      assert.throws(
        () => loadRuntimeConfig(productionEnv({
          ASTRANULL_BUNDLED_STAGING_OIDC: '1',
          ASTRANULL_PUBLIC_BASE_URL: DO_HOST,
          ASTRANULL_OIDC_ISSUER: 'https://idp.example.com/',
          ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
        })),
        /ASTRANULL_BUNDLED_STAGING_OIDC=1 mints tokens stamped with ASTRANULL_OIDC_ISSUER/,
      );
    });

    it('refuses to start when a real IdP is configured but the fixture flag is left on', () => {
      assert.throws(
        () => loadRuntimeConfig(productionEnv({
          ASTRANULL_BUNDLED_STAGING_OIDC: '1',
          ASTRANULL_PUBLIC_BASE_URL: DO_HOST,
          ASTRANULL_OIDC_ISSUER: 'https://idp.example.com/',
          ASTRANULL_OIDC_JWKS_URL: 'https://login.microsoftonline.com/tid/discovery/v2.0/keys',
          ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
        })),
        /Set ASTRANULL_BUNDLED_STAGING_OIDC=0 when adopting a real identity provider/,
      );
    });

    it('accepts the completed cutover as a pure config change, with the mint route off', () => {
      // The whole point: adopting a real IdP needs no code edit. Clearing the flag also does
      // not disturb the deployment profile, because both specs declare it explicitly.
      const config = loadRuntimeConfig(productionEnv({
        ASTRANULL_PUBLIC_BASE_URL: DO_HOST,
        ASTRANULL_OIDC_ISSUER: 'https://idp.example.com/',
        ASTRANULL_OIDC_JWKS_URL: 'https://login.microsoftonline.com/tid/discovery/v2.0/keys',
        ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
      }));
      assert.equal(config.bundledStagingOidc, false, 'the unauthenticated mint must be off');
      assert.equal(config.bundledStagingStaffLogin, false);
      assert.equal(config.deploymentProfile, 'hosted-staging', 'profile must not shift');
    });
  });
});