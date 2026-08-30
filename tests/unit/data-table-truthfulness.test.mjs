import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const TABLE_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/components/ui/table.tsx', import.meta.url),
  'utf8',
);
const INTERACTIVE_ROW_SOURCES = [
  'page-components.tsx',
  'functional-surfaces.tsx',
].map((file) => readFileSync(
  new URL(`../../apps/web/react/src/pages/${file}`, import.meta.url),
  'utf8',
));

describe('DataTable truthfulness and row semantics', () => {
  it('renders a refresh failure above non-empty cached rows instead of dropping either signal', () => {
    assert.match(TABLE_SOURCE, /const failureMessage = loadError\?\.trim\(\) \?\? ''/);
    assert.match(
      TABLE_SOURCE,
      /\{failureMessage \? \([\s\S]*<TableLoadError message=\{failureMessage\} onRetry=\{onRetry\} retainedRows \/>[\s\S]*<DataTableChrome/,
    );
    assert.match(TABLE_SOURCE, /Showing previously loaded rows below\./);
  });

  it('still replaces a false empty claim with the load error when no rows are cached', () => {
    assert.match(
      TABLE_SOURCE,
      /items\.length === 0[\s\S]*failureMessage \? <TableLoadError message=\{failureMessage\} onRetry=\{onRetry\} \/> : empty/,
    );
  });

  it('keeps the row accessible while nested controls own pointer and keyboard events', () => {
    assert.match(TABLE_SOURCE, /const \{ className: rowClassName, onClick, onKeyDown, \.\.\.restRowProps \} = rowProps/);
    assert.match(TABLE_SOURCE, /<tr[\s\S]*\{\.\.\.restRowProps\}[\s\S]*onClick=\{onClick[\s\S]*onKeyDown=\{onKeyDown/);
    assert.match(TABLE_SOURCE, /target\.closest\('a, button, input, select, textarea, summary/);
    assert.match(TABLE_SOURCE, /if \(nestedInteractiveOwnsEvent\(event\)\) return;/);
    assert.match(TABLE_SOURCE, /if \(event\.target !== event\.currentTarget\) return;/);
    assert.match(TABLE_SOURCE, /onClick\(event\)/);
    assert.match(TABLE_SOURCE, /onKeyDown\(event\)/);
    assert.doesNotMatch(TABLE_SOURCE, /tabIndex: ignoredTabIndex|data-table-row-action/);
    for (const source of INTERACTIVE_ROW_SOURCES) {
      assert.doesNotMatch(source, /role:\s*['"]link['"]/);
      assert.match(source, /tabIndex:\s*0/);
    }
  });
});
