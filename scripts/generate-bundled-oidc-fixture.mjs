#!/usr/bin/env node
/**
 * Generates the bundled staging OIDC fixture — the RSA keypair that signs auth tokens for
 * `ASTRANULL_BUNDLED_STAGING_OIDC=1` deployments.
 *
 * The output file is gitignored: it is a signing trust root, and an earlier version of it was
 * committed to this public repo (see .gitignore). Because git history is public and permanent,
 * that key is burned and src/lib/bundledStagingOidc.mjs refuses to load it.
 *
 * Existing fixtures are preserved unless --force is passed: regenerating invalidates every
 * token already minted against the old key, so it must be a deliberate act rather than a
 * side effect of running the test suite.
 */
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, '..', 'ops', 'staging');
const outPath = path.join(outDir, 'bundled-oidc-fixture.json');

const force = process.argv.includes('--force');
const quiet = process.argv.includes('--quiet');

/** sha256 of the RSA modulus of the key published in this repo's git history. Public material. */
const BURNED_KEY_MODULUS_SHA256 =
  '15cf684e4a87c50221e687b7f189e04c05bc31c974e970bae8f9a72e60075f2e';

/**
 * True when an on-disk fixture is the compromised key. Existing checkouts keep that file after
 * it was untracked, so without this the "already present" skip below would preserve a key the
 * runtime refuses — turning every test run and startup into a hard failure. Replacing it is
 * always safe: it authenticates nothing anywhere.
 */
function existingFixtureIsBurned(file) {
  try {
    const modulus = JSON.parse(readFileSync(file, 'utf8'))?.public_jwk?.n;
    if (typeof modulus !== 'string' || modulus === '') return false;
    return createHash('sha256').update(modulus).digest('hex') === BURNED_KEY_MODULUS_SHA256;
  } catch {
    return false; // Unreadable or malformed: leave it alone and let the runtime report it.
  }
}

if (existsSync(outPath) && !force) {
  if (existingFixtureIsBurned(outPath)) {
    console.log(
      'bundled-oidc-fixture: on-disk fixture is the key published in this repository\'s git '
      + 'history and cannot be used. Replacing it with a fresh keypair.',
    );
  } else {
    if (!quiet) console.log(`bundled-oidc-fixture: already present at ${outPath} (use --force to rotate)`);
    process.exit(0);
  }
}

mkdirSync(outDir, { recursive: true });

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = publicKey.export({ format: 'jwk' });
publicJwk.kid = 'hosted-staging-rsa-1';
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

const fixture = {
  issuer_suffix: '/staging-oidc',
  audience: 'astranull-hosted-staging',
  kid: 'hosted-staging-rsa-1',
  public_jwk: publicJwk,
  private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  note: 'STAGING-ONLY fixture IdP — not for customer secrets or production tenant data. Never commit this file.',
};

writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
// Fingerprint is of public key material only, so it is safe to print and is what an operator
// compares against the deployed key to confirm a rotation actually took effect.
const fingerprint = createHash('sha256').update(publicJwk.n).digest('hex');
console.log(`wrote ${outPath}`);
console.log(`public key modulus sha256: ${fingerprint}`);
