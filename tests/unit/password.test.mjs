import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assessPassword,
  hashPassword,
  needsRehash,
  verifyPassword,
} from '../../src/lib/password.mjs';

describe('password hashing', () => {
  it('hashes and verifies a password with the encoded scrypt parameters', async () => {
    const encoded = await hashPassword('N7!vR2#qL9@z');
    assert.match(
      encoded,
      /^scrypt\$N=16384,r=8,p=1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/,
    );
    assert.equal(await verifyPassword('N7!vR2#qL9@z', encoded), true);
    assert.equal(await verifyPassword('wrong-password', encoded), false);
    assert.equal(needsRehash(encoded), false);
  });

  it('returns false instead of throwing for malformed encodings', async () => {
    for (const encoded of [
      null,
      '',
      'sha256$abc',
      'scrypt$N=nope,r=8,p=1$salt$hash',
      'scrypt$N=3,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'scrypt$N=16384,r=8,p=1$***$***',
      'scrypt$N=1073741824,r=8,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ]) {
      assert.equal(await verifyPassword('N7!vR2#qL9@z', encoded), false, String(encoded));
    }
  });

  it('detects hashes with weaker stored parameters and malformed hashes', () => {
    const hash = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const salt = 'MDEyMzQ1Njc4OWFiY2RlZg';
    assert.equal(needsRehash(`scrypt$N=8192,r=8,p=1$${salt}$${hash}`), true);
    assert.equal(needsRehash(`scrypt$N=16384,r=4,p=1$${salt}$${hash}`), true);
    assert.equal(needsRehash(`scrypt$N=16384,r=8,p=1$${salt}$${hash}`), false);
    assert.equal(needsRehash('malformed'), true);
  });
});

describe('password policy', () => {
  it('accepts a strong password', () => {
    assert.deepEqual(
      assessPassword('N7!vR2#qL9@z', { email: 'alice@example.com' }),
      { ok: true, failures: [] },
    );
  });

  it('rejects every password policy violation with machine-readable codes', () => {
    assert.ok(assessPassword('Aa1!short').failures.includes('too_short'));
    assert.deepEqual(assessPassword('Aa1!'.repeat(51)).failures, ['too_long']);
    assert.ok(
      assessPassword('alllowercasepassword').failures.includes('insufficient_character_classes'),
    );
    assert.ok(
      assessPassword('Alice-Portal9!Z', { email: 'ALICE@example.com' }).failures
        .includes('contains_email_local_part'),
    );
    assert.ok(assessPassword('Password123!').failures.includes('common_password'));
    assert.deepEqual(assessPassword(null), { ok: false, failures: ['invalid_type'] });
    assert.ok(
      assessPassword('SecureXPhrase9!', { email: 'x@example.com' }).failures
        .includes('contains_email_local_part'),
    );
  });
});
