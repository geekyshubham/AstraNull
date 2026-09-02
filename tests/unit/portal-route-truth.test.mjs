import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DETAIL_ROUTE_ITEMS,
  NAV_ITEMS,
  ROUTE_BY_ID,
  resolvePortalRoute,
} from '../../apps/web/react/src/lib/navigation.ts';
import { PROTOTYPE_SURFACES } from '../../apps/web/react/src/lib/prototype-manifest.ts';

describe('React portal route truth', () => {
  it('allows the prototype manifest to claim only real React routes', () => {
    const claimed = PROTOTYPE_SURFACES.filter((surface) => surface.routeId);
    for (const surface of claimed) {
      assert.ok(ROUTE_BY_ID.has(surface.routeId), `${surface.id} claims missing route ${surface.routeId}`);
    }

    const claimedIds = [...new Set(claimed.map((surface) => surface.routeId))].sort();
    const realIds = [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => item.id).sort();
    assert.deepEqual(claimedIds, realIds);
    assert.equal(PROTOTYPE_SURFACES.find((surface) => surface.id === 'public-landing')?.routeId, undefined);
  });

  it('resolves documented hash and direct-path aliases', () => {
    assert.equal(resolvePortalRoute('/app', '#checks'), 'checks');
    assert.equal(resolvePortalRoute('/checks', ''), 'checks');
    assert.equal(resolvePortalRoute('/app', ''), 'dashboard');
    assert.equal(resolvePortalRoute('/', ''), 'dashboard');
    assert.equal(resolvePortalRoute('/internal/admin', ''), 'admin');
    assert.equal(resolvePortalRoute('/internal/soc', ''), 'internal-soc');
  });

  it('never coerces unknown or removed routes to dashboard', () => {
    assert.equal(resolvePortalRoute('/app', '#unknown'), 'not-found');
    assert.equal(resolvePortalRoute('/unknown', ''), 'not-found');
    assert.equal(resolvePortalRoute('/onboarding', ''), 'not-found');
    assert.equal(resolvePortalRoute('/waf-posture', ''), 'not-found');
  });
});
