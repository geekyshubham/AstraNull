import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { NAV_GROUP_LABELS, NAV_ITEMS, ROUTE_BY_ID, routeCrumb } from '../../apps/web/react/src/lib/navigation.ts';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.ts';

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
    assert.match(shell, /if \(!entityTitle\) return `\$\{crumb\.label\} · \$\{groupLabel\} · AstraNull`;/);
    assert.match(shell, /const documentTitle = documentTitleFor\(route, crumb, entityTitle\);/);
    assert.match(shell, /document\.title = documentTitle;/);
  });

  it('names the open record in detail-view document titles without touching the breadcrumb', () => {
    assert.match(shell, /export function useEntityDocumentTitle\(title\?: string\)/);
    assert.match(shell, /return `\$\{entityTitle\} · \$\{listLabel \? sentenceStart\(listLabel\) : groupLabel\} · AstraNull`;/);
    assert.match(shell, /entityTitleState\?\.route === route \? entityTitleState\.title : null/);
    assert.match(shell, /<EntityTitleContext\.Provider value=\{setEntityTitle\}>/);
    assert.match(shell, /<b aria-current="page">\{crumb\.label\}<\/b>/);
  });

  it('shows the workspace name in the sidebar footer and keeps the tenant id as its tooltip', () => {
    assert.match(shell, /<b className="sidebar-account-name" title=\{tenantId\}>\{tenantName \|\| tenantId\}<\/b>/);
    assert.match(shell, /<span className="sidebar-account-name">Staff session<\/span>/);
    assert.match(shell, /<div className="sidebar-account" title=\{accountTitle\}>/);
  });

  it('keeps every sidebar footer action named, including icon-only and collapsed states', () => {
    const foot = shell.slice(shell.indexOf('<div className="sidebar-foot">'), shell.indexOf('</aside>'));
    assert.match(foot, /onClick=\{logout\}\s*aria-label="Sign out"\s*title="Sign out"/);
    assert.match(foot, /aria-label="Public site"\s*title="Public site"/);
    assert.match(foot, /label=\{collapseLabel\}\s*className="sidebar-foot-btn sidebar-collapse"/);
    assert.doesNotMatch(shell.slice(shell.indexOf('<div className="sidebar-head">'), shell.indexOf('<nav className="nav-scroll"')), /sidebar-collapse/);
  });

  it('paints the sidebar head, nav, and footer edge to edge instead of inside aside padding', () => {
    const frame = styles.slice(styles.lastIndexOf('/* ── Sidebar frame'));
    assert.match(frame, /\.sidebar,\s*\.sidebar-collapsed \.sidebar \{[^}]*padding: var\(--space-5\) 0 0;/);
    assert.match(frame, /\.sidebar \.nav-scroll \{[^}]*padding-inline: var\(--sidebar-pad-x\);/);
    assert.match(frame, /\.sidebar \.sidebar-foot \{[^}]*margin: 0;[^}]*border-top: 1px solid var\(--border-soft\);[^}]*padding: var\(--space-3\) var\(--sidebar-pad-x\)/);
    assert.match(frame, /@media \(pointer: coarse\) \{[\s\S]*?\.sidebar-foot \[data-ui='button'\]\.sidebar-foot-btn \{\s*min-height: 44px;/);
    assert.doesNotMatch(frame, /#[0-9a-f]{3,8}\b|rgba?\(/i);
  });

  it('highlights Targets while a run or the legacy runs list is open', () => {
    assert.match(shell, /'run-detail': 'targets',\s*runs: 'targets',/);
  });

  it('exposes a skip link that targets the labelled main content region', () => {
    assert.match(shell, /className="skip-link" href="#portal-main"/);
    assert.match(shell, /id="portal-main"/);
    assert.match(shell, /aria-label=\{`\$\{crumb\.label\} workspace`\}/);
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

describe('principal-aware crumbs and nav groups', () => {
  const crumbText = (routeId, principal) => {
    const crumb = routeCrumb(ROUTE_BY_ID.get(routeId), principal);
    return `${NAV_GROUP_LABELS[crumb.group]} › ${crumb.label}`;
  };
  const sidebarGroups = (role, principal) =>
    new Set(
      NAV_ITEMS.filter((item) => canAccessRoute(role, item.id, { principal }))
        .map((item) => NAV_GROUP_LABELS[routeCrumb(item, principal).group]),
    );

  it('never shows a customer soc session a Staff group and files its SOC console under Governance', () => {
    assert.equal(canAccessRoute('soc', 'internal-soc', { principal: 'customer' }), true);
    const groups = sidebarGroups('soc', 'customer');
    assert.equal(groups.has('Staff'), false);
    assert.equal(groups.has('Governance'), true);
    assert.equal(crumbText('internal-soc', 'customer'), 'Governance › SOC console');
    assert.equal(crumbText('internal-soc', undefined), 'Governance › SOC console');
  });

  it('reads a customer queue detail as a validation high-scale request', () => {
    assert.equal(crumbText('queue-detail', 'customer'), 'Validation › High-scale request');
  });

  it('keeps the Staff crumb for staff sessions', () => {
    assert.equal(crumbText('internal-soc', 'staff'), `Staff › ${ROUTE_BY_ID.get('internal-soc').label}`);
    assert.equal(crumbText('queue-detail', 'staff'), `Staff › ${ROUTE_BY_ID.get('queue-detail').label}`);
  });

  it('leaves every other route crumb unchanged for customers', () => {
    const target = ROUTE_BY_ID.get('targets');
    assert.deepEqual(routeCrumb(target, 'customer'), { group: target.group, label: target.label });
  });
});
