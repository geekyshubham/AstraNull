import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summarizePortalCoverageByFile } from '../../scripts/portal-coverage-file-report.mjs';

const cell = (file, state = 'success') => ({ action: `apps/web/react/src/${file}#Owner:activate:abc`, state });

test('summaries group every reconciliation bucket by source file and rank the largest gaps first', () => {
  const rows = summarizePortalCoverageByFile({
    portal: {
      covered: [cell('a.tsx'), cell('b.tsx')],
      uncovered: [cell('a.tsx'), cell('a.tsx', 'reload'), cell('c.tsx')],
      unclassifiedStates: [cell('c.tsx'), cell('c.tsx', 'busy')],
      notApplicable: [cell('b.tsx')],
    },
  });
  assert.deepEqual(rows.map((row) => row.file), ['apps/web/react/src/c.tsx', 'apps/web/react/src/a.tsx', 'apps/web/react/src/b.tsx']);
  assert.deepEqual(rows[0], { file: 'apps/web/react/src/c.tsx', covered: 0, uncovered: 1, unclassified: 2, notApplicable: 0 });
  assert.deepEqual(rows[1], { file: 'apps/web/react/src/a.tsx', covered: 1, uncovered: 2, unclassified: 0, notApplicable: 0 });
});

test('route and dataset authorization obligations are not attributed to a source file', () => {
  const rows = summarizePortalCoverageByFile({ portal: { covered: [{ action: 'route:dashboard' }, { action: 'dataset:audit' }, cell('a.tsx')], uncovered: [], unclassifiedStates: [], notApplicable: [] } });
  assert.deepEqual(rows.map((row) => row.file), ['apps/web/react/src/a.tsx']);
});

test('an empty portal section yields no rows', () => {
  assert.deepEqual(summarizePortalCoverageByFile({}), []);
});
