import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { portalGeometryProbe, visualSweepFailures } from '../../scripts/lib/portal-visual-results.mjs';

const clean = () => ({
  route: 'targets', theme: 'dark', viewport: 'mobile', axeStatus: 'completed', axe: [], diagnostics: [],
  geometry: { pageOverflowX: 0, offscreen: [], clippedText: [], smallTargets: [] },
});

function textGeometry(style = {}, rect = {}) {
  const bounds = { left: 0, right: 1, width: 1, height: 1, ...rect };
  const element = {
    tagName: 'SPAN', id: 'status-label', classList: [], textContent: 'Risk decisions',
    childNodes: [{}], scrollWidth: 111, clientWidth: bounds.width, parentElement: null,
    closest: () => null, getAttribute: () => null, getBoundingClientRect: () => bounds,
  };
  const document = {
    documentElement: { clientWidth: 375, scrollWidth: 375 }, body: {},
    querySelectorAll: (selector) => selector === 'body *' || selector.startsWith('h1,') ? [element] : [],
  };
  const getComputedStyle = () => ({
    visibility: 'visible', display: 'block', opacity: '1', position: 'absolute',
    overflow: 'hidden', overflowX: 'hidden', clip: 'rect(0px, 0px, 0px, 0px)', ...style,
  });
  return JSON.parse(JSON.stringify(runInNewContext(`(${portalGeometryProbe.toString()})()`, { document, getComputedStyle })));
}

test('geometry does not flag fully clipped one-pixel screen-reader labels as truncated text', () => {
  assert.deepEqual(textGeometry().clippedText, []);
  for (const [style, rect] of [
    [{ clip: 'auto' }, {}],
    [{ clip: 'rect(0px, 1px, 1px, 0px)' }, {}],
    [{ position: 'static' }, {}],
    [{}, { width: 80, right: 80, height: 20 }],
  ]) assert.equal(textGeometry(style, rect).clippedText.length, 1, JSON.stringify({ style, rect }));
});

test('visual sweeps fail closed for missing or failing assessments', () => {
  assert.equal(visualSweepFailures([clean()]).length, 0);
  assert.ok(visualSweepFailures([]).length);
  for (const delta of [
    { error: 'navigation failed' },
    { diagnostics: [{ classification: 'unclassified' }] },
    { axe: [{ id: 'color-contrast' }] },
    { axeStatus: 'running' },
    { geometry: undefined },
    { geometry: { ...clean().geometry, pageOverflowX: 2 } },
    { geometry: { ...clean().geometry, offscreen: ['button'] } },
    { geometry: { ...clean().geometry, clippedText: ['heading'] } },
    { geometry: { ...clean().geometry, smallTargets: ['button 20x20'] } },
  ]) assert.ok(visualSweepFailures([{ ...clean(), ...delta }]).length, JSON.stringify(delta));
});

test('visual sweeps retain explicit fixture limitations without hiding application errors', () => {
  const entry = { ...clean(), diagnostics: [{ classification: 'audit_stylesheet_csp_refetch' }] };
  assert.deepEqual(visualSweepFailures([entry]), []);
  entry.diagnostics.push({ classification: 'unclassified', message: 'application crash' });
  assert.equal(visualSweepFailures([entry]).length, 1);
  assert.deepEqual(visualSweepFailures([{ ...clean(), viewport: 'tablet', axeStatus: 'not_run_tablet' }]), []);
  assert.deepEqual(visualSweepFailures([{ ...clean(), viewport: 'desktop', geometry: { ...clean().geometry, smallTargets: ['button'] } }]), []);
});
