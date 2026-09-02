import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const shell = readFileSync(new URL('../../apps/web/react/src/components/layout/app-shell.tsx', import.meta.url), 'utf8');
const styles = readFileSync(new URL('../../apps/web/react/src/styles.css', import.meta.url), 'utf8');
const explanation = readFileSync(
  new URL('../../apps/web/react/src/components/findings/finding-explanation-panel.tsx', import.meta.url),
  'utf8'
);

/**
 * The authenticated portal is a single-page app. Without these, every authenticated route
 * shares one generic document title, keyboard users restart at the navigation on each
 * route change, and incomplete metric rows leak the grid's hairline colour.
 */
describe('portal shell navigation semantics', () => {
  it('gives every authenticated route a distinct document title', () => {
    assert.match(shell, /document\.title = `\$\{current\.label\} · \$\{NAV_GROUP_LABELS\[current\.group\]\} · AstraNull`/);
    assert.match(shell, /\}, \[current\.label, current\.group\]\)/);
  });

  it('exposes a skip link that targets the labelled main content region', () => {
    assert.match(shell, /className="skip-link" href="#portal-main"/);
    assert.match(shell, /id="portal-main"/);
    assert.match(shell, /aria-label=\{`\$\{current\.label\} workspace`\}/);
    assert.match(shell, /tabIndex=\{-1\}/);
  });

  it('moves focus to content on route change but not on first mount', () => {
    assert.match(shell, /routeArrivedRef\.current = true;[\s\S]*return;/);
    assert.match(shell, /mainRef\.current\?\.focus\(\{ preventScroll: true \}\)/);
    assert.match(shell, /\}, \[route\]\)/);
  });

  it('does not paint a focus ring on the programmatically focused region', () => {
    assert.match(styles, /\.main:focus \{\s*outline: none;\s*\}/);
  });

  it('paints metric hairlines per cell so incomplete rows show no orphan strip', () => {
    const start = styles.indexOf('.kpi-row {');
    const rowBlock = styles.slice(start, styles.indexOf('}', start));
    assert.match(rowBlock, /background: var\(--bg\)/);
    assert.doesNotMatch(rowBlock, /background: var\(--border-soft\)/);
    assert.match(styles.slice(start), /\.kpi-cell \{[\s\S]*box-shadow: -1px 0 0 var\(--border-soft\), 0 -1px 0 var\(--border-soft\)/);
  });

  it('keeps evidence panel headings one level below their card title', () => {
    assert.doesNotMatch(explanation, /<h4>/);
    assert.match(explanation, /<h3>Evidence provenance<\/h3>/);
    assert.match(explanation, /<h3>Linked evidence unavailable<\/h3>/);
  });

  it('keeps select placement math equal to the rendered menu offset', () => {
    const select = readFileSync(new URL('../../apps/web/react/src/components/ui/select.tsx', import.meta.url), 'utf8');
    const gap = Number(/const SELECT_MENU_GAP = (\d+);/.exec(select)?.[1]);
    const spacing = Number(/--space-2:\s*(\d+)px/.exec(styles)?.[1]);
    // The last `.select-menu` rule in the cascade owns the real offset.
    const lastMenuRule = styles.slice(styles.lastIndexOf('.select-menu {'));
    const offsetToken = /top: calc\(100% \+ var\((--space-\d)\)\)/.exec(lastMenuRule)?.[1];

    assert.equal(offsetToken, '--space-2', 'select menu offset token changed');
    assert.equal(spacing, 8);
    assert.equal(gap, spacing, 'SELECT_MENU_GAP must equal the rendered menu offset');
  });
});
