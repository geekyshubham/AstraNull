import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { summarizeAccessibilityChecks } from '../../scripts/run-live-ui-accessibility-matrix.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relative) => readFileSync(path.join(ROOT, relative), 'utf8');

describe('portal accessibility hardening', () => {
  it('removes closed custom listboxes from layout and keyboard order', () => {
    const select = read('apps/web/react/src/components/ui/select.tsx');
    const css = read('apps/web/react/src/styles.css');
    assert.match(select, /hidden={!open \|\| disabled}/);
    assert.match(select, /tabIndex={open && !disabled \? 0 : -1}/);
    assert.match(css, /\.select-menu\[hidden\] \{\s*display: none;/m);
  });

  it('contains mobile drawer focus, closes on Escape, and restores prior focus', () => {
    const select = read('apps/web/react/src/components/ui/select.tsx');
    const shell = read('apps/web/react/src/components/layout/app-shell.tsx');
    assert.match(select, /open && event\.key === 'Escape'[\s\S]*event\.preventDefault\(\);[\s\S]*event\.stopPropagation\(\);/m);
    assert.doesNotMatch(select, /document\.addEventListener\('keydown'/);
    assert.match(shell, /event\.key === 'Escape'[\s\S]*event\.defaultPrevented/m);
    assert.match(shell, /event\.key === 'Escape'[\s\S]*setSidebarOpen\(false\)/m);
    assert.match(shell, /event\.key !== 'Tab'/);
    assert.match(shell, /previousFocus\?\.focus\(\)/);
    assert.match(shell, /aria-modal={sidebarOpen \? true : undefined}/);
    assert.match(shell, /expanded={sidebarOpen} controls="portal-navigation"/);
  });

  it('uses valid nested definition lists for agent bootstrap facts', () => {
    const agents = read('apps/web/react/src/pages/functional-surfaces.tsx');
    assert.match(agents, /<div className="agents-bootstrap-facts"[\s\S]*?<dl>[\s\S]*?<dt>Registration limit<\/dt>[\s\S]*?<\/dl>/m);
    assert.match(agents, /<div className="agents-summary-grid"[\s\S]*?<dl>[\s\S]*?<dt>Registered<\/dt>[\s\S]*?<\/dl>/m);
    assert.doesNotMatch(agents, /<dl className="agents-(?:bootstrap-facts|summary-grid)"[\s\S]*?<div>/m);
  });

  it('wraps long target custody metadata and preserves coarse-pointer target width', () => {
    const target = read('apps/web/react/src/pages/target-detail-view.tsx');
    const css = read('apps/web/react/src/styles.css');
    assert.match(target, /\.target-check-choice \{[^}]*min-width: 44px;[^}]*min-height: 44px;/);
    assert.match(target, /\.kv-meta \{[^}]*overflow-wrap: anywhere;[^}]*word-break: break-word;[^}]*white-space: normal;/);
    const targetGroup = read('apps/web/react/src/pages/target-group-detail-view.tsx');
    assert.match(targetGroup, /\.tg-detail-view \.check-choice \{[^}]*min-width: 44px;[^}]*min-height: 44px;/);
    assert.match(css, /\.sidebar-foot \.field\.sidebar-role \.select-display \{\s*min-height: 44px;/m);
    assert.match(css, /@media \(pointer: coarse\)[\s\S]*?\.btn-sm \{\s*min-width: 44px;\s*min-height: 44px;/m);
  });

  it('makes every audited horizontal overflow region keyboard-focusable and named', () => {
    const target = read('apps/web/react/src/pages/target-detail-view.tsx');
    const finding = read('apps/web/react/src/pages/finding-detail-view.tsx');
    const proof = read('apps/web/react/src/components/runs/run-proof-panels.tsx');
    const heatmap = read('apps/web/react/src/components/charts/vector-heatmap.tsx');
    const install = read('apps/web/react/src/components/agents/agent-install-matrix.tsx');
    const landing = read('apps/web/react/src/pages/public-pages.tsx');
    const css = read('apps/web/react/src/styles.css');

    assert.match(target, /className="table-wrap" tabIndex=\{0\} role="region" aria-label="Ownership and eligibility, scrollable"/);
    assert.match(target, /className="codeblock" tabIndex=\{0\} role="region" aria-label="WAF posture technical details"/);
    assert.match(finding, /className="code" tabIndex=\{0\} role="region" aria-label="Finding custody chain YAML"/);
    assert.match(proof, /className="truth-table-viz" tabIndex=\{0\} role="region" aria-labelledby="truth-table-heading"/);
    assert.match(heatmap, /className="heatmap"\s*tabIndex=\{0\}\s*role="region"\s*aria-label="Vector coverage matrix, scrollable"/m);
    assert.doesNotMatch(heatmap, /HEATMAP_CELL_STYLE|style=\{HEATMAP_CELL_STYLE/);
    assert.match(install, /className="codeblock"[\s\S]*role="tabpanel"[\s\S]*aria-label=\{`\$\{label\} install commands`\}[\s\S]*tabIndex=\{0\}/m);
    assert.match(landing, /className="public-compare table-wrap"\s*tabIndex=\{0\}\s*role="region"\s*aria-label="AstraNull capability comparison, scrollable"/m);
    assert.match(css, /@media \(max-width: 900px\)[\s\S]*?\.public-compare \{\s*overflow-x: auto;/m);
    assert.match(css, /pre\.verdict-explanation-value[\s\S]*overflow: visible/);
  });

  it('keeps clickable rows focusable and ignores keyboard events from nested controls', () => {
    const table = read('apps/web/react/src/components/ui/table.tsx');
    assert.match(table, /\{\.\.\.restRowProps\}/);
    assert.match(table, /if \(event\.target !== event\.currentTarget\) return;/);
    assert.doesNotMatch(table, /tabIndex: ignoredTabIndex|data-table-row-action/);
    assert.match(table, /aria-label={`\$\{columns\.map\(\(column\) => column\.label\)\.join\(', '\)\} data table`}/);
  });

  it('derives live matrix passes from completed checks, never route authorization alone', () => {
    const authorizedOnly = summarizeAccessibilityChecks({ routeAuthorized: true });
    assert.deepEqual(
      [authorizedOnly.axe_status, authorizedOnly.keyboard_status, authorizedOnly.screen_reader_status],
      ['fail', 'fail', 'fail'],
    );

    const checked = summarizeAccessibilityChecks({
      routeAuthorized: true,
      axeCompleted: true,
      axeIssues: { critical: 0, serious: 0, moderate: 0, minor: 0 },
      keyboardCompleted: true,
      keyboardIssues: [],
      screenReaderCompleted: true,
      screenReaderIssues: [],
    });
    assert.deepEqual(
      [checked.axe_status, checked.keyboard_status, checked.screen_reader_status],
      ['pass', 'pass', 'pass'],
    );

    const unauthorized = summarizeAccessibilityChecks({ routeAuthorized: false });
    assert.deepEqual(
      [unauthorized.axe_status, unauthorized.keyboard_status, unauthorized.screen_reader_status],
      ['skip', 'skip', 'skip'],
    );

    const live = read('scripts/run-live-ui-accessibility-matrix.mjs');
    assert.match(live, /new AxeBuilder\(\{ page \}\)\.withTags\(AXE_TAGS\)\.analyze\(\)/);
    assert.match(live, /runKeyboardChecks\(page\)/);
    assert.match(live, /runScreenReaderSemanticChecks\(page\)/);
    assert.doesNotMatch(live, /unauthorized \? 'fail' : 'pass'/);
  });
});
