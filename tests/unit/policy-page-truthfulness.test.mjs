import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/page-components.tsx', import.meta.url),
  'utf8',
);
const REFINED_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/refined/policies-refined.tsx', import.meta.url),
  'utf8',
);
const CREATE_PANEL_SOURCE = REFINED_SOURCE.slice(
  REFINED_SOURCE.indexOf('function CreateSchedulePanel('),
  REFINED_SOURCE.indexOf('function readStateFilter('),
);
const policyStart = SOURCE.indexOf('export function PolicyPage(');
const policyEnd = SOURCE.indexOf('export function SupportPage(', policyStart);
const POLICY_SOURCE = SOURCE.slice(policyStart, policyEnd);
assert.ok(policyStart >= 0 && policyEnd > policyStart, 'PolicyPage source block must be discoverable');
assert.ok(CREATE_PANEL_SOURCE.length > 0, 'single create-schedule panel source must be discoverable');

describe('Policy page truthfulness contract', () => {
  it('writes exact domain schedules sequentially and retries only failed domains', () => {
    assert.match(POLICY_SOURCE, /for \(const targetId of policyTargetIds\)/);
    assert.match(POLICY_SOURCE, /body: \{ \.\.\.bodyBase, target_id: targetId \}/);
    assert.match(POLICY_SOURCE, /setPolicyTargetIds\(\[\.\.\.failedIds\]\)/);
    assert.doesNotMatch(POLICY_SOURCE, /target_group_id:|\/v1\/target-groups/);
    assert.match(CREATE_PANEL_SOURCE, /<DomainPicker/);
    assert.match(POLICY_SOURCE, /isPolicyTargetCompatible\(selectedPolicyCheck, target\)/);
  });
  it('does not inject a hidden default safe window from the collapsed optional section', () => {
    const safeWindowDetails = CREATE_PANEL_SOURCE.match(/<details className="rf-disclosure full">[\s\S]*?<\/details>/)?.[0] ?? '';
    assert.ok(safeWindowDetails, 'optional safe-window details must render in the single create panel');
    assert.doesNotMatch(safeWindowDetails, /defaultValue="(?:Mon|02:00|04:00|UTC)"/);
    assert.match(safeWindowDetails, /name="safe_window_day" value=\{form\.windowDay\}/);
    assert.match(safeWindowDetails, /<input name="safe_window_start" type="time" \/>/);
    assert.match(safeWindowDetails, /<input name="safe_window_end" type="time" \/>/);
    assert.match(POLICY_SOURCE, /const \[policyWindowDay, setPolicyWindowDay\] = useState\(''\);/);
    assert.match(POLICY_SOURCE, /const hasSafeWindow = \[day, start, end\]\.some\(Boolean\)/);
    assert.match(POLICY_SOURCE, /hasSafeWindow && !safeWindowValues\.every\(Boolean\)/);
    assert.match(POLICY_SOURCE, /const safe_windows = hasSafeWindow \? \[\{ day, start, end, timezone \}\] : \[\]/);
  });

  it('shows the schedule timezone as a visible, validated field instead of a hidden default', () => {
    assert.match(CREATE_PANEL_SOURCE, /<span>Schedule timezone \(IANA\)<\/span>/);
    assert.match(CREATE_PANEL_SOURCE, /aria-invalid=\{!timezoneValid \|\| undefined\}/);
    assert.match(CREATE_PANEL_SOURCE, /!timezoneValid \|\| busy !== ''/);
    assert.match(POLICY_SOURCE, /if \(!isValidTimezone\(timezone\)\)/);
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
    for (const scheduleSource of [POLICY_SOURCE]) {
      assert.doesNotMatch(scheduleSource, /event(?:_|-|\s+)driven/i);
      assert.doesNotMatch(scheduleSource, /event(?:_|-|\s+)trigger/i);
    }
  });





  it('keeps the bound target, group, and check out of schedule edits', () => {
    const editDialog = REFINED_SOURCE.slice(REFINED_SOURCE.indexOf('export function ScheduleEditDialog('), REFINED_SOURCE.indexOf('export function ScheduleActions('));
    assert.match(editDialog, /aria-label="Immutable binding"/);
    for (const field of ['target_id', 'target_group_id', 'check_id']) {
      assert.doesNotMatch(editDialog, new RegExp(`changed\\.${field}`));
    }
  });
});
