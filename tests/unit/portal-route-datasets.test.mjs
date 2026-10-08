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

  it('places direct Targets in scope with bounded inventory hydration', () => {
    // Current release: targets-first scope (ADR-0008, shared-shell review); groups are secondary.
    const targetsIndex = NAV_ITEMS.findIndex((item) => item.id === 'targets');

    assert.notEqual(targetsIndex, -1);
    assert.equal(NAV_ITEMS.some((item) => item.id === 'target-groups'), false);
    assert.deepEqual(PORTAL_ROUTE_DATASETS.targets, ['targets']);
  });

  it('never hydrates a customer target-group dataset on any route', () => {
    for (const datasets of Object.values(PORTAL_ROUTE_DATASETS)) assert.ok(!datasets.includes('targetGroups'));
  });

  it('keeps a representative route hydrate bounded', () => {
    const routeDatasets = PORTAL_ROUTE_DATASETS.findings;
    const requestDatasets = [...CORE_PORTAL_DATASETS, ...routeDatasets];

    // Findings render from authoritative records, and coverage is only counted from verdicts
    // with evidence bound to the exact run, so the finding-related datasets are required.
    assert.deepEqual(routeDatasets, ['targets', 'checks', 'runs', 'findings', 'evidence']);
    assert.deepEqual(requestDatasets, [...CORE_PORTAL_DATASETS, ...routeDatasets]);
    assert.ok(requestDatasets.length <= 10, `findings requested ${requestDatasets.length} datasets`);
  });

  it('keeps every route hydrate bounded', () => {
    for (const [route, datasets] of Object.entries(PORTAL_ROUTE_DATASETS)) {
      const total = CORE_PORTAL_DATASETS.length + datasets.length;
      const limit = route === 'dashboard' ? 13 : 12;
      assert.ok(total <= limit, `${route} requested ${total} datasets`);
    }
    assert.ok(PORTAL_ROUTE_DATASETS.dashboard.includes('targets'), 'dashboard needs declared target names for finding and run labels');
  });
});
