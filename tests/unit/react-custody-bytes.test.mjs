import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  CUSTODY_DIGEST_UNAVAILABLE_MESSAGE,
  sha256Hex,
  sha256HexBytes,
} from '../../apps/web/react/src/lib/custody.ts';

function nodeSha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

describe('react custody byte fingerprinting', () => {
  it('hashes Uint8Array and ArrayBuffer input identically to node:crypto', async () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const expected = nodeSha256(Buffer.from(bytes));
    assert.equal(await sha256HexBytes(bytes), expected);
    assert.equal(await sha256HexBytes(bytes.buffer), expected);
  });

  it('hashes only the viewed slice of a Uint8Array', async () => {
    const backing = new Uint8Array([9, 9, 1, 2, 3, 9]);
    const view = backing.subarray(2, 5);
    assert.equal(await sha256HexBytes(view), nodeSha256(Buffer.from([1, 2, 3])));
  });

  it('keeps sha256Hex(text) equal to hashing its UTF-8 bytes', async () => {
    const text = 'evidence ✓ export';
    assert.equal(await sha256Hex(text), nodeSha256(Buffer.from(text, 'utf8')));
    assert.equal(await sha256Hex(text), await sha256HexBytes(new TextEncoder().encode(text)));
  });

  it('throws a clear error when Web Crypto is unavailable', async (t) => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true, writable: true });
    t.after(() => {
      if (original) Object.defineProperty(globalThis, 'crypto', original);
    });
    await assert.rejects(() => sha256HexBytes(new Uint8Array([1])), { message: CUSTODY_DIGEST_UNAVAILABLE_MESSAGE });
    assert.match(CUSTODY_DIGEST_UNAVAILABLE_MESSAGE, /Web Crypto/);
  });
});
