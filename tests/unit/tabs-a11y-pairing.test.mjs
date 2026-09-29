import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import ts from 'typescript';

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

function tabsUsages(file) {
  const text = readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const found = [];
  (function visit(node) {
    if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) && node.tagName.getText(sf) === 'Tabs') {
      const names = node.attributes.properties.filter(ts.isJsxAttribute).map((a) => a.name.getText(sf));
      const panelAttr = node.attributes.properties.find((a) => ts.isJsxAttribute(a) && a.name.getText(sf) === 'getPanelId');
      const prefix = panelAttr?.initializer?.getText(sf).match(/`([a-z0-9-]+)-panel-\$\{/)?.[1] ?? null;
      found.push({ line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, names, prefix });
    }
    ts.forEachChild(node, visit);
  })(sf);
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
      const text = readFileSync(file, 'utf8');
      const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      (function visit(node) {
        if (ts.isJsxText(node) && /^\s*[A-Za-z_$][\w.$]*\s*(\?|&&)\s*\(?\s*$/.test(node.getText(sf))) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          leaks.push(`${path.relative(SRC, file)}:${line} renders "${node.getText(sf).trim()}" as text`);
        }
        ts.forEachChild(node, visit);
      })(sf);
    }
    assert.deepEqual(leaks, []);
  });
});
