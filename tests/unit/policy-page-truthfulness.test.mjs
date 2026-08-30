import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/page-components.tsx', import.meta.url),
  'utf8',
);
const TARGET_GROUP_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/target-group-detail-view.tsx', import.meta.url),
  'utf8',
);
const policyStart = SOURCE.indexOf('export function PolicyPage(');
const policyEnd = SOURCE.indexOf('export function IntegrationPage(', policyStart);
const POLICY_SOURCE = SOURCE.slice(policyStart, policyEnd);
const TARGET_GROUP_SCHEDULE_SOURCE = TARGET_GROUP_SOURCE.match(
  /<form className="product-form schedule-builder"[\s\S]*?<\/form>/,
)?.[0] ?? '';

assert.ok(policyStart >= 0 && policyEnd > policyStart, 'PolicyPage source block must be discoverable');
assert.ok(TARGET_GROUP_SCHEDULE_SOURCE, 'target-group schedule form source must be discoverable');

describe('Policy page truthfulness contract', () => {
  it('does not inject a hidden default safe window from the collapsed optional section', () => {
    const safeWindowDetails = POLICY_SOURCE.match(/<details className="full">[\s\S]*?<\/details>/)?.[0] ?? '';
    assert.ok(safeWindowDetails, 'optional safe-window details must render');
    assert.doesNotMatch(safeWindowDetails, /defaultValue="(?:Mon|02:00|04:00|UTC)"/);
    assert.match(POLICY_SOURCE, /const hasSafeWindow = safeWindowValues\.some\(Boolean\)/);
    assert.match(POLICY_SOURCE, /hasSafeWindow && !safeWindowValues\.every\(Boolean\)/);
    assert.match(POLICY_SOURCE, /const safe_windows = hasSafeWindow \? \[\{ day, start, end, timezone \}\] : \[\]/);
  });

  it('does not expose unsupported event-driven or event-trigger controls', () => {
    const cadenceOptionsSource = SOURCE.match(
      /const POLICY_CADENCE_OPTIONS: SelectOption\[\] = \[([\s\S]*?)\n\];/,
    )?.[1] ?? '';
    const uiCadences = [...cadenceOptionsSource.matchAll(/\{ value: '([^']+)'/g)]
      .map((match) => match[1]);

    assert.deepEqual(uiCadences, ['manual', 'daily', 'weekly', 'monthly']);
    assert.doesNotMatch(cadenceOptionsSource, /event_driven|Event-driven/i);
    assert.doesNotMatch(SOURCE, /POLICY_EVENT_TRIGGER_OPTIONS/);
    for (const scheduleSource of [POLICY_SOURCE, TARGET_GROUP_SCHEDULE_SOURCE]) {
      assert.doesNotMatch(scheduleSource, /event(?:_|-|\s+)driven/i);
      assert.doesNotMatch(scheduleSource, /event(?:_|-|\s+)trigger/i);
    }
  });

  it('keeps target-group safe-window day and time controls blank by default', () => {
    const dayControl = TARGET_GROUP_SCHEDULE_SOURCE.match(
      /<select name="safe_window_day"[^>]*>/,
    )?.[0] ?? '';
    const startControl = TARGET_GROUP_SCHEDULE_SOURCE.match(
      /<input name="safe_window_start"[^>]*>/,
    )?.[0] ?? '';
    const endControl = TARGET_GROUP_SCHEDULE_SOURCE.match(
      /<input name="safe_window_end"[^>]*>/,
    )?.[0] ?? '';

    assert.match(dayControl, /defaultValue=""/);
    assert.doesNotMatch(dayControl, /defaultValue="(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"/);
    assert.ok(startControl, 'target-group safe-window start control must render');
    assert.ok(endControl, 'target-group safe-window end control must render');
    assert.doesNotMatch(startControl, /(?:defaultValue|value)="[^"]+"/);
    assert.doesNotMatch(endControl, /(?:defaultValue|value)="[^"]+"/);
  });

  it('reports each sequential multi-group result and selects only failures for retry', () => {
    assert.match(POLICY_SOURCE, /for \(const targetGroupId of policyTargetGroupIds\) \{[\s\S]*try \{[\s\S]*successes\.push/);
    assert.match(POLICY_SOURCE, /failures\.push\(\{/);
    assert.match(POLICY_SOURCE, /Created \$\{successes\.length\} of \$\{policyTargetGroupIds\.length\} policies/);
    assert.match(POLICY_SOURCE, /Successful writes were retained; only failed target groups remain selected for retry\./);
    assert.match(POLICY_SOURCE, /setPolicyTargetGroupIds\(failures\.map\(\(failure\) => failure\.targetGroupId\)\)/);
    assert.match(POLICY_SOURCE, /The writes succeeded; refresh the page instead of creating them again\./);
  });
});
