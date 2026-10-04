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
const TARGET_GROUP_SCHEDULE_SOURCE = TARGET_GROUP_SOURCE.match(
  /<form className="product-form schedule-builder"[\s\S]*?<\/form>/,
)?.[0] ?? '';

assert.ok(policyStart >= 0 && policyEnd > policyStart, 'PolicyPage source block must be discoverable');
assert.ok(CREATE_PANEL_SOURCE.length > 0, 'single create-schedule panel source must be discoverable');
assert.ok(TARGET_GROUP_SCHEDULE_SOURCE, 'target-group schedule form source must be discoverable');

describe('Policy page truthfulness contract', () => {
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

  it('reports each sequential multi-group result and retains only failed exact bindings for retry', () => {
    assert.match(POLICY_SOURCE, /for \(const targetGroupId of policyTargetGroupIds\) \{[\s\S]*const targetId = policyTargetBindings\[targetGroupId\]\?\.selectedTargetId[\s\S]*successes\.push/);
    assert.match(POLICY_SOURCE, /body: \{ \.\.\.bodyBase, target_group_id: targetGroupId, target_id: targetId \}/);
    assert.match(POLICY_SOURCE, /failures\.push\(\{/);
    assert.match(POLICY_SOURCE, /Created \$\{successes\.length\} of \$\{policyTargetGroupIds\.length\} policies/);
    assert.match(POLICY_SOURCE, /Successful writes were retained; only failed exact target bindings remain selected for retry\./);
    assert.match(POLICY_SOURCE, /const failedGroupIds = new Set\(failures\.map\(\(failure\) => failure\.targetGroupId\)\)/);
    assert.match(POLICY_SOURCE, /if \(failedGroupIds\.has\(targetGroupId\)\) retained\[targetGroupId\] = binding/);
    assert.match(POLICY_SOURCE, /The writes succeeded; refresh the page instead of creating them again\./);
  });

  it('requires one explicit active target per selected group and displays immutable target identity', () => {
    assert.match(POLICY_SOURCE, /`\/v1\/target-groups\/\$\{encodeURIComponent\(targetGroupId\)\}`/);
    assert.match(POLICY_SOURCE, /target\.deleted_at == null && target\.archived_at == null/);
    assert.match(CREATE_PANEL_SOURCE, /then one exact target in each\. Targets are never assigned automatically, and the bound identity cannot change after creation\./);
    assert.doesNotMatch(POLICY_SOURCE, /setPolicyTargetGroupIds\(\[groupId\]\)/);
    assert.match(POLICY_SOURCE, /const policyBindingsReady = policyTargetGroupIds\.length > 0/);
    assert.match(CREATE_PANEL_SOURCE, /const submitDisabled = noGroups \|\| noChecks \|\| !form\.checkId \|\| !form\.bindingsReady/);
    assert.match(REFINED_SOURCE, /label: 'Exact target'/);
    assert.match(REFINED_SOURCE, /buildDetailHref\('target-detail', target\.targetId\)/);
    assert.match(REFINED_SOURCE, /description: `\$\{effectivePolicyTargetKind\(target\)\.replace\(\/_\/g, ' '\)\} · \$\{targetId\}`/);
    assert.match(CREATE_PANEL_SOURCE, /Exactly these records are written/);
  });

  it('carries a caller target only when it is the exact, compatible target in the named group', () => {
    assert.match(POLICY_SOURCE, /getHashQueryParam\('check'\)/);
    assert.match(POLICY_SOURCE, /getHashQueryParam\('target'\)/);
    assert.match(POLICY_SOURCE, /preferredTargetId && targets\.some\(\s*\(target\) => getString\(target, \['id'\], ''\) === preferredTargetId && isPolicyTargetCompatible\(preferredCheck, target\)/);
    assert.doesNotMatch(POLICY_SOURCE, /targets\[0\]/);
    assert.match(POLICY_SOURCE, /if \(!policyCheckId && safeChecks\.length === 1\) setPolicyCheckId/);
  });

  it('keeps the bound target, group, and check out of schedule edits', () => {
    const editDialog = REFINED_SOURCE.slice(REFINED_SOURCE.indexOf('export function ScheduleEditDialog('), REFINED_SOURCE.indexOf('export function ScheduleActions('));
    assert.match(editDialog, /aria-label="Immutable binding"/);
    for (const field of ['target_id', 'target_group_id', 'check_id']) {
      assert.doesNotMatch(editDialog, new RegExp(`changed\\.${field}`));
    }
  });
});
