import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DETAIL_ROUTE_ITEMS, NAV_ITEMS } from '../../apps/web/react/src/lib/navigation.ts';
import {
  CORE_PORTAL_DATASETS,
  PORTAL_ROUTE_DATASETS,
} from '../../apps/web/react/src/lib/types.ts';

describe('portal route dataset policy', () => {
  it('covers every real route and reserves an empty dataset for unknown locations', () => {
    const routeIds = [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => item.id).sort();
    const datasetRouteIds = Object.keys(PORTAL_ROUTE_DATASETS).filter((id) => id !== 'not-found').sort();
    assert.deepEqual(datasetRouteIds, routeIds);
    assert.deepEqual(PORTAL_ROUTE_DATASETS['not-found'], []);
  });

  it('places Targets immediately below Target groups with bounded inventory hydration', () => {
    const targetGroupIndex = NAV_ITEMS.findIndex((item) => item.id === 'target-groups');

    assert.notEqual(targetGroupIndex, -1);
    assert.equal(NAV_ITEMS[targetGroupIndex + 1]?.id, 'targets');
    assert.deepEqual(PORTAL_ROUTE_DATASETS.targets, ['targets', 'targetGroups']);
  });

  it('hydrates every dataset rendered by Target Groups', () => {
    const routeDatasets = PORTAL_ROUTE_DATASETS['target-groups'];

    assert.deepEqual(routeDatasets, ['targetGroups', 'agents', 'runs', 'findings', 'evidence']);
    assert.ok(
      CORE_PORTAL_DATASETS.length + routeDatasets.length <= 12,
      'Target Groups hydration must stay within the global route bound',
    );
  });

  it('keeps a representative route hydrate bounded', () => {
    const routeDatasets = PORTAL_ROUTE_DATASETS.environments;
    const requestDatasets = [...CORE_PORTAL_DATASETS, ...routeDatasets];

    // Environments render from authoritative /v1/environments records, and coverage is only
    // counted from verdicts with evidence bound to the exact run, so both datasets are required.
    assert.deepEqual(routeDatasets, ['environments', 'targetGroups', 'agents', 'runs', 'findings', 'evidence']);
    assert.deepEqual(requestDatasets, [...CORE_PORTAL_DATASETS, ...routeDatasets]);
    assert.ok(requestDatasets.length <= 10, `environments requested ${requestDatasets.length} datasets`);
  });

  it('keeps every route hydrate bounded', () => {
    for (const [route, datasets] of Object.entries(PORTAL_ROUTE_DATASETS)) {
      const total = CORE_PORTAL_DATASETS.length + datasets.length;
      assert.ok(total <= 12, `${route} requested ${total} datasets`);
    }
  });
});
