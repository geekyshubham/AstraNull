import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  normalizeTargetInput,
  sanitizeClientTargetMetadata,
  targetDedupeKey,
  TargetValidationError,
} from '../../src/contracts/targetManagement.mjs';

describe('target management trust boundary', () => {
  it('canonicalizes target kinds and values for deterministic dedupe', () => {
    assert.deepEqual(
      normalizeTargetInput({ kind: 'domain', value: 'WWW.Example.COM.' }),
      { kind: 'fqdn', value: 'www.example.com', normalized_value: 'www.example.com', metadata: {}, dropped_fields: [] },
    );
    assert.equal(
      targetDedupeKey({ kind: 'url', value: 'HTTPS://Example.COM:443/path#fragment' }),
      'url\u0000https://example.com/path',
    );
    assert.equal(normalizeTargetInput({ kind: 'ip', value: '2001:0DB8::1' }).value, '2001:db8::1');
  });

  it('rejects host:port values when the declared kind is ip', () => {
    assert.throws(
      () => normalizeTargetInput({ kind: 'ip', value: '203.0.113.10:443' }),
      (error) => error instanceof TargetValidationError
        && error.field === 'value'
        && /kind "tcp"/.test(error.message),
    );
    assert.throws(() => normalizeTargetInput({ kind: 'ip', value: '[2001:db8::1]:443' }), TargetValidationError);
  });

  it('allows only safe absolute HTTP(S) target URLs', () => {
    assert.throws(() => normalizeTargetInput({ kind: 'url', value: 'ftp://example.com/file' }), TargetValidationError);
    assert.throws(() => normalizeTargetInput({ kind: 'url', value: 'https://user:secret@example.com/' }), TargetValidationError);
    assert.equal(normalizeTargetInput({ kind: 'url', value: 'https://EXAMPLE.com/a?q=1#ignored' }).value, 'https://example.com/a?q=1');
  });

  it('removes ownership, verification, eligibility, source, and provenance at every metadata depth', () => {
    const result = sanitizeClientTargetMetadata({
      notes: 'customer note',
      agent_id: 'agt_1',
      ownership_status: 'verified',
      source: 'trusted_connector',
      nested: {
        verification_state: 'verified',
        eligibility: 'eligible',
        direct_origin_ip: '203.0.113.10',
      },
      provenance: { actor: 'spoofed' },
    });

    assert.deepEqual(result.metadata, {
      notes: 'customer note',
      agent_id: 'agt_1',
      nested: { direct_origin_ip: '203.0.113.10' },
    });
    assert.deepEqual(result.dropped_fields.sort(), [
      'nested.eligibility',
      'nested.verification_state',
      'ownership_status',
      'provenance',
      'source',
    ]);
  });
});
