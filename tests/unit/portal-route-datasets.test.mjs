import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DETAIL_ROUTE_ITEMS, NAV_ITEMS } from '../../apps/web/react/src/lib/navigation.ts';
import {
  CORE_PORTAL_DATASETS,
  PORTAL_ROUTE_DATASETS,
} from '../../apps/web/react/src/lib/types.ts';

describe('portal route dataset policy', () => {
  it('covers every route declared by the portal navigation', () => {
    const routeIds = [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => item.id).sort();
    assert.deepEqual(Object.keys(PORTAL_ROUTE_DATASETS).sort(), routeIds);
  });

  it('keeps a representative route hydrate bounded', () => {
    const routeDatasets = PORTAL_ROUTE_DATASETS.environments;
    const requestDatasets = [...CORE_PORTAL_DATASETS, ...routeDatasets];

    assert.deepEqual(routeDatasets, ['targetGroups', 'agents', 'runs', 'findings']);
    assert.deepEqual(requestDatasets, [...CORE_PORTAL_DATASETS, ...routeDatasets]);
    assert.ok(requestDatasets.length <= 8, `environments requested ${requestDatasets.length} datasets`);
  });
});
