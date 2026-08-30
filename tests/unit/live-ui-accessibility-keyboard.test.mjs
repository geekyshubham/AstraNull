import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  runKeyboardChecks,
  summarizeAccessibilityChecks,
} from '../../scripts/run-live-ui-accessibility-matrix.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RUNNER = readFileSync(path.join(ROOT, 'scripts/run-live-ui-accessibility-matrix.mjs'), 'utf8');
const stop = (signature, overrides = {}) => ({
  boundary: null,
  focusable: true,
  visible: true,
  indicator: true,
  signature,
  ...overrides,
});

function keyboardPage(states, { originReady = true, pressError = null } = {}) {
  const events = [];
  let sentinelInstalled = false;
  const remaining = [...states];
  const page = {
    async evaluate(_callback, argument) {
      if (typeof argument === 'string') {
        if (!sentinelInstalled) {
          sentinelInstalled = true;
          events.push('sentinel:focus');
          return originReady;
        }
        sentinelInstalled = false;
        events.push('sentinel:remove');
        return undefined;
      }
      events.push('stop:inspect');
      assert.ok(remaining.length > 0, 'keyboard traversal inspected more states than the fixture provided');
      return remaining.shift();
    },
    keyboard: {
      async press(key) {
        events.push(`press:${key}`);
        if (pressError) throw pressError;
      },
    },
  };
  return { events, page };
}

describe('canonical live UI accessibility runner', () => {
  it('keeps Axe on a BrowserContext page and preserves login and diagnostic contracts', () => {
    assert.match(RUNNER, /const context = await browser\.newContext\(\);[\s\S]*const page = await context\.newPage\(\);/m);
    assert.match(RUNNER, /new AxeBuilder\(\{ page \}\)\.withTags\(AXE_TAGS\)\.analyze\(\)/);
    assert.match(RUNNER, /finally \{\s*await context\.close\(\);\s*await browser\.close\(\);\s*\}/m);
    assert.match(RUNNER, /locator\('#login-user-id'\)\.fill\(ACCESSIBILITY_RUNNER_IDENTITY/);
    assert.match(RUNNER, /keyboard traversal executed \(\$\{keyboard\.checks\} checks\)/);
    assert.match(RUNNER, /keyboard issues: \$\{keyboard\.issues\.join\('; '\)\}/);
    assert.match(
      RUNNER,
      /const runnerPassword = process\.env\[ACCESSIBILITY_RUNNER_PASSWORD_ENV\];\s*delete process\.env\[ACCESSIBILITY_RUNNER_PASSWORD_ENV\];\s*ensurePlaywrightCore\(\);/m,
    );
    assert.doesNotMatch(RUNNER, /page\.unroute\(/);
  });

  it('starts at a temporary first-DOM sentinel and treats document or sentinel wrap as exhaustion', async () => {
    assert.match(RUNNER, /document\.body\.prepend\(sentinel\);[\s\S]*sentinel\.focus\(\{ preventScroll: true \}\);/m);
    assert.match(RUNNER, /try \{[\s\S]*\} finally \{[\s\S]*document\.getElementById\(sentinelId\)\?\.remove\(\);/m);

    for (const boundary of ['document', 'sentinel']) {
      const { events, page } = keyboardPage([
        stop('10'),
        stop('20'),
        { boundary },
      ]);
      const result = await runKeyboardChecks(page);

      assert.deepEqual(result, { completed: true, checks: 2, issues: [] });
      assert.equal(events.filter((event) => event === 'stop:inspect').length, 3);
      assert.deepEqual(events.slice(0, 2), ['sentinel:focus', 'press:Tab']);
      assert.equal(events.at(-1), 'sentinel:remove');
    }

    const wrappedToFirst = keyboardPage([stop('10'), stop('20'), stop('10')]);
    assert.deepEqual(
      await runKeyboardChecks(wrappedToFirst.page),
      { completed: true, checks: 2, issues: [] },
    );
    assert.equal(wrappedToFirst.events.at(-1), 'sentinel:remove');
  });

  it('still reports real invalid stops, absent indicators, no controls, and stalled navigation', async () => {
    const invalid = keyboardPage([
      stop('10', { focusable: false, visible: false, indicator: false }),
      { boundary: 'document' },
    ]);
    const invalidResult = await runKeyboardChecks(invalid.page);
    assert.equal(invalidResult.checks, 1);
    assert.deepEqual(invalidResult.issues, [
      '1 sampled tab stop(s) were hidden or not focusable',
      '1 sampled tab stop(s) lacked a visible focus indicator',
    ]);

    const empty = keyboardPage([{ boundary: 'document' }]);
    assert.deepEqual(await runKeyboardChecks(empty.page), {
      completed: true,
      checks: 0,
      issues: ['No reachable keyboard-focusable control found'],
    });

    const stalled = keyboardPage([stop('10'), stop('10')]);
    assert.deepEqual(await runKeyboardChecks(stalled.page), {
      completed: true,
      checks: 1,
      issues: ['Tab navigation did not advance through distinct controls'],
    });
  });

  it('removes the sentinel even when traversal throws', async () => {
    const fixture = keyboardPage([], { pressError: new Error('keyboard unavailable') });
    await assert.rejects(runKeyboardChecks(fixture.page), /keyboard unavailable/);
    assert.equal(fixture.events.at(-1), 'sentinel:remove');
  });

  it('never turns route authorization alone into an accessibility pass', () => {
    const authorizedOnly = summarizeAccessibilityChecks({ routeAuthorized: true });
    assert.deepEqual(
      [authorizedOnly.axe_status, authorizedOnly.keyboard_status, authorizedOnly.screen_reader_status],
      ['fail', 'fail', 'fail'],
    );
    assert.deepEqual(authorizedOnly.issues, { critical: 0, serious: 0, moderate: 2, minor: 0 });

    const unauthorized = summarizeAccessibilityChecks({ routeAuthorized: false });
    assert.deepEqual(
      [unauthorized.axe_status, unauthorized.keyboard_status, unauthorized.screen_reader_status],
      ['skip', 'skip', 'skip'],
    );
    assert.equal(unauthorized.issues.serious, 1);
  });
});
