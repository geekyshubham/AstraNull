import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { designVariantStorageKey, resolveDesignVariant } from '../../apps/web/react/src/lib/design-variant.ts';

function installWindow(hash, stored = {}) {
  const store = new Map(Object.entries(stored));
  const writes = [];
  const reads = [];
  globalThis.window = {
    location: { hash, pathname: '/app', search: '' },
    localStorage: {
      getItem(key) {
        reads.push(key);
        return store.has(key) ? store.get(key) : null;
      },
      setItem(key, value) {
        writes.push([key, value]);
        store.set(key, value);
      },
    },
  };
  return { reads, writes };
}

describe('design variant persistence (customer layout switch is staff-only)', () => {
  let previousWindow;
  beforeEach(() => { previousWindow = globalThis.window; });
  afterEach(() => { globalThis.window = previousWindow; });

  it('ignores a stored layout and never writes storage when persist is false', () => {
    const { reads, writes } = installWindow('#runs', { [designVariantStorageKey('runs')]: 'refined' });
    assert.equal(resolveDesignVariant('runs', false), 'classic');
    assert.deepEqual(reads, []);
    assert.deepEqual(writes, []);
  });

  it('still honours the explicit hash override without persisting it', () => {
    const { writes } = installWindow('#runs?variant=refined');
    assert.equal(resolveDesignVariant('runs', false), 'refined');
    assert.deepEqual(writes, []);
  });

  it('keeps the stored preference and hash persistence for staff (persist true)', () => {
    const stored = installWindow('#findings', { [designVariantStorageKey('findings')]: 'refined' });
    assert.equal(resolveDesignVariant('findings', true), 'refined');
    assert.deepEqual(stored.writes, []);
    const hashed = installWindow('#findings?variant=refined');
    assert.equal(resolveDesignVariant('findings'), 'refined');
    assert.deepEqual(hashed.writes, [[designVariantStorageKey('findings'), 'refined']]);
  });

  it('defaults to classic with no hash and no stored value', () => {
    installWindow('#runs');
    assert.equal(resolveDesignVariant('runs', false), 'classic');
    assert.equal(resolveDesignVariant('runs', true), 'classic');
  });
});
