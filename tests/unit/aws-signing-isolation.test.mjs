import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { validateAwsComposeSigningIsolation } from '../../scripts/validate-aws-compose-secrets.mjs';

function model() {
  return { services: {
    'control-plane': { environment: { ASTRANULL_KMS_SIGNING_BEARER_TOKEN_FILE: '/run/astranull-signing/token' },
      volumes: [{ type: 'bind', source: '/operator/signing', target: '/run/astranull-signing', read_only: true }] },
    'probe-worker': { environment: {}, volumes: [] },
  } };
}

describe('AWS evidence signing isolation', () => {
  it('permits control-only read-only signing mounts without reading credentials', () => {
    assert.equal(validateAwsComposeSigningIsolation(model()), true);
    const short = model();
    short.services['control-plane'].volumes = ['/operator/signing:/run/astranull-signing:ro'];
    assert.equal(validateAwsComposeSigningIsolation(short), true);
  });

  for (const key of ['ASTRANULL_KMS_SIGNING_BEARER_TOKEN', 'ASTRANULL_KMS_SIGNING_BEARER_TOKEN_FILE',
    'ASTRANULL_EVIDENCE_SIGNING_KEY', 'ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON']) {
    it(`rejects worker projection of ${key}, including blank values`, () => {
      const candidate = model();
      candidate.services['probe-worker'].environment[key] = '';
      assert.throws(() => validateAwsComposeSigningIsolation(candidate), /must not receive evidence signer/);
    });
  }

  it('rejects writable signing mounts in both rendered and short syntax', () => {
    const candidate = model();
    candidate.services['control-plane'].volumes[0].read_only = false;
    assert.throws(() => validateAwsComposeSigningIsolation(candidate), /read-only/);
    candidate.services['control-plane'].volumes = ['/operator/signing:/run/astranull-signing:rw'];
    assert.throws(() => validateAwsComposeSigningIsolation(candidate), /read-only/);
  });

  it('rejects a shared signing source even mounted at a different worker path', () => {
    const candidate = model();
    candidate.services['probe-worker'].volumes = ['/operator/signing:/worker/credentials:ro'];
    assert.throws(() => validateAwsComposeSigningIsolation(candidate), /must not receive signing mounts/);
  });

  it('rejects signing-path mounts from a different source or an individual file', () => {
    const candidate = model();
    candidate.services['probe-worker'].volumes = [{ source: '/other/token', target: '/run/astranull-signing/token', read_only: true }];
    assert.throws(() => validateAwsComposeSigningIsolation(candidate), /must not receive signing mounts/);
  });

  it('does not turn an absent signer into an acceptance claim', () => {
    assert.equal(validateAwsComposeSigningIsolation({ services: { 'control-plane': {}, 'probe-worker': {} } }), true);
  });
});
