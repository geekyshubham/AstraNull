import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  appendInternalAudit,
  listInternalAudit,
} from '../../src/services/internalManagement.mjs';
import { freshStore } from '../helpers/reset.mjs';

/**
 * The in-memory internal audit listing must clamp `limit` to the same window the Postgres backend
 * enforces at src/persistence/postgres/internalManagementRepository.mjs:847, which is
 * `Math.min(Math.max(Number(filters.limit) || 100, 1), 500)`.
 *
 * Before the clamp, listInternalAudit did a bare `items.slice(0, filters.limit ?? 100)` over a copy
 * of the WHOLE log, and src/server.mjs hands the raw query param straight through as
 * `Number(url.searchParams.get('limit') ?? 100)`. So on any non-postgres deployment a staff caller
 * holding staff:audit:read could ask for ?limit=99999999 and dump the entire internal audit log in
 * a single JSON.stringify. Production runs postgres, so this was backend divergence rather than a
 * live outage — but the unbounded backend is the one that answers in local, dev-json and memory
 * deployments.
 *
 * These exercise the shipped export directly (no local reimplementation of the clamp) so the bound
 * being asserted is the one callers actually get. The numbers are pinned as literals because the
 * Postgres path spells them inline too; there is no shared exported constant to import yet.
 */
describe('internal audit listing limit clamp', () => {
  beforeEach(() => {
    freshStore();
  });

  /** Append `count` distinct audit entries so slice boundaries are observable. */
  function seedAudit(count) {
    for (let i = 0; i < count; i += 1) {
      appendInternalAudit(
        { staffId: 'staff_actor', staffRole: 'internal_admin' },
        { action: 'internal.audit.seed', resource_id: `res_${i}` },
      );
    }
  }

  it('caps an oversized limit at 500 instead of returning the whole log', () => {
    seedAudit(620);
    assert.equal(listInternalAudit({ limit: 99999999 }).length, 500);
    assert.equal(listInternalAudit({ limit: 501 }).length, 500);
    assert.equal(listInternalAudit({ limit: 500 }).length, 500);
  });

  it('keeps limits inside the window verbatim', () => {
    seedAudit(120);
    // The deployed caller in tests/integration/public-internal-management-api.test.mjs asks for 50.
    assert.equal(listInternalAudit({ limit: 50 }).length, 50);
    assert.equal(listInternalAudit({ limit: 1 }).length, 1);
    assert.equal(listInternalAudit({ limit: 120 }).length, 120);
  });

  it('falls back to 100 when no limit is supplied', () => {
    seedAudit(150);
    assert.equal(listInternalAudit().length, 100);
    assert.equal(listInternalAudit({}).length, 100);
  });

  /**
   * Two edge cases move deliberately here, both TOWARD the Postgres behaviour rather than away.
   *
   * limit=0 previously returned [] (slice(0, 0)) and now returns the default page, because `0 || 100`
   * is 100 — which is exactly what the Postgres path already returned for 0. limit=abc previously
   * returned [] too (slice(0, NaN) is []); the Postgres path never had that bug, since `NaN || 100`
   * is 100. The silent-empty-result was in-memory only, which is further reason to converge on the
   * Postgres expression instead of preserving it.
   */
  it('treats zero, negative and non-numeric limits the way the Postgres path does', () => {
    seedAudit(150);
    assert.equal(listInternalAudit({ limit: 0 }).length, 100);
    assert.equal(listInternalAudit({ limit: Number('abc') }).length, 100);
    assert.equal(listInternalAudit({ limit: 'abc' }).length, 100);
    // Negative used to slice from the END (slice(0, -5) drops the last 5); floor is now 1.
    assert.equal(listInternalAudit({ limit: -5 }).length, 1);
  });

  it('clamps after filtering, so a filtered page is not padded from other actions', () => {
    seedAudit(30);
    for (let i = 0; i < 4; i += 1) {
      appendInternalAudit(
        { staffId: 'staff_actor', staffRole: 'internal_admin' },
        { action: 'break_glass.activated', resource_id: `bg_${i}` },
      );
    }
    const filtered = listInternalAudit({ action: 'break_glass.activated', limit: 99999999 });
    assert.equal(filtered.length, 4);
    assert.ok(filtered.every((entry) => entry.action === 'break_glass.activated'));
  });
});
