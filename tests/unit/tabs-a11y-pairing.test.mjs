import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
// typescript@7 is the native compiler and has no JS compiler API, so parse TSX with the
// oxc parser that Vite (already a dev dependency) exposes.
import { parseAst } from 'vite';

// Every <Tabs> must pair its tabs with panels (aria-controls ↔ role="tabpanel" + aria-labelledby).
// The shared component only emits aria-controls/ids when getPanelId/getTabId are passed, so a caller
// that omits them silently ships tabs with no programmatic link to their content.
const SRC = new URL('../../apps/web/react/src/', import.meta.url).pathname;

function tsxFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return tsxFiles(full);
    return entry.name.endsWith('.tsx') ? [full] : [];
  });
}

function parseTsx(file) {
  const text = readFileSync(file, 'utf8');
  const nodes = [];
  (function visit(node) {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    if (typeof node.type === 'string') nodes.push(node);
    for (const value of Object.values(node)) visit(value);
  })(parseAst(text, { lang: 'tsx' }, file));
  const lineOf = (node) => text.slice(0, node.start).split('\n').length;
  return { text, nodes, lineOf };
}

function tabsUsages(file) {
  const { text, nodes, lineOf } = parseTsx(file);
  const found = [];
  for (const node of nodes) {
    if (node.type !== 'JSXOpeningElement' || node.name?.name !== 'Tabs') continue;
    const attributes = node.attributes.filter((a) => a.type === 'JSXAttribute');
    const names = attributes.map((a) => a.name.name);
    const panelAttr = attributes.find((a) => a.name.name === 'getPanelId');
    const initializer = panelAttr?.value ? text.slice(panelAttr.value.start, panelAttr.value.end) : '';
    const prefix = initializer.match(/`([a-z0-9-]+)-panel-\$\{/)?.[1] ?? null;
    found.push({ line: lineOf(node), names, prefix });
  }
  return { text, found };
}

describe('tabs accessibility pairing', () => {
  it('every <Tabs> passes getTabId and getPanelId, and its panels are rendered with matching ids', () => {
    const problems = [];
    let checked = 0;
    for (const file of tsxFiles(SRC)) {
      if (file.endsWith(path.join('components', 'ui', 'tabs.tsx'))) continue;
      const { text, found } = tabsUsages(file);
      for (const usage of found) {
        checked += 1;
        const where = `${path.relative(SRC, file)}:${usage.line}`;
        for (const required of ['getTabId', 'getPanelId']) {
          if (!usage.names.includes(required)) problems.push(`${where} is missing ${required}`);
        }
        // Static prefixes are checked end to end: the panel must exist and point back at its tab.
        if (usage.prefix && !text.includes(`id="${usage.prefix}-panel-`) && !text.includes(`id={\`${usage.prefix}-panel-`)) {
          problems.push(`${where} declares panels "${usage.prefix}-panel-*" but renders none`);
        }
        if (usage.prefix && !text.includes(`aria-labelledby="${usage.prefix}-tab-`) && !text.includes(`aria-labelledby={\`${usage.prefix}-tab-`)) {
          problems.push(`${where} panels do not reference "${usage.prefix}-tab-*" via aria-labelledby`);
        }
      }
    }
    assert.ok(checked >= 10, `expected to find the portal's Tabs usages, found ${checked}`);
    assert.deepEqual(problems, []);
  });

  it('tab panels contain no JSX text that is really a leaked expression', () => {
    // Wrapping a bare `cond ? (<A/>) : (<B/>)` panel body in <div role="tabpanel"> without braces
    // still type-checks: the condition becomes literal text and BOTH branches render. Catch it.
    const leaks = [];
    for (const file of tsxFiles(SRC)) {
      const { nodes, lineOf } = parseTsx(file);
      for (const node of nodes) {
        if (node.type === 'JSXText' && /^\s*[A-Za-z_$][\w.$]*\s*(\?|&&)\s*\(?\s*$/.test(node.raw)) {
          leaks.push(`${path.relative(SRC, file)}:${lineOf(node)} renders "${node.raw.trim()}" as text`);
        }
      }
    }
    assert.deepEqual(leaks, []);
  });
});
