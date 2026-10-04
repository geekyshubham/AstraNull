import { useEffect, useId, useMemo, useRef, useState, type FormEvent, type HTMLAttributes, type ReactNode } from 'react';
import {
  Archive,
  CalendarClock,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  ListFilter,
  Lock,
  Pause,
  Plus,
  ShieldCheck
} from 'lucide-react';
import {
  effectivePolicyTargetKind,
  isPolicyTargetCompatible,
  policySupportedTargetKinds,
  TargetGroupPicker
} from '../../components/policies/target-group-picker';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { Select, type SelectOption } from '../../components/ui/select';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { FormModal, useConfirmModal } from '../../lib/crud-ui';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../../lib/route-params';
// @ts-ignore Plain ESM keeps executive terminology directly testable with node:test.
import { plainCheckName } from '../../lib/plain-language.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatNumber } from '../../lib/utils';
import './policies-refined.css';

/** Mirrors PolicyPage's per-group exact-target binding state. */
export type RefinedPolicyTargetBinding = {
  targets: DataItem[];
  selectedTargetId: string;
  loading: boolean;
  error: string;
};

/**
 * The create-schedule form state and handlers, owned by PolicyPage. The form renders inline
 * (progressive disclosure), but every value, validation rule, and write path is the parent's.
 */
export interface PolicyCreateFormModel {
  open: boolean;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  targetGroups: DataItem[];
  selectedGroupIds: string[];
  onTargetGroupsChange: (ids: string[]) => void;
  bindings: Record<string, RefinedPolicyTargetBinding>;
  onSelectTarget: (targetGroupId: string, targetId: string) => void;
  onRetryTargets: (targetGroupId: string) => void;
  bindingsReady: boolean;
  selectedCheck: DataItem | null;
  checkId: string;
  checkOptions: SelectOption[];
  onCheckChange: (checkId: string) => void;
  cadence: string;
  cadenceOptions: SelectOption[];
  onCadenceChange: (cadence: string) => void;
  expectedVerdict: string;
  verdictOptions: SelectOption[];
  onExpectedVerdictChange: (verdict: string) => void;
  timezone: string;
  onTimezoneChange: (timezone: string) => void;
  windowDay: string;
  onWindowDayChange: (day: string) => void;
}

export interface PoliciesRefinedProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  busy: string;
  message: string;
  error: string;
  canWritePolicies: boolean;
  safeChecks: DataItem[];
  onCreateSchedule: () => void;
  onActionResult: (message: string, error: string) => void;
  createForm: PolicyCreateFormModel;
}

type StateFilter = 'all' | 'active' | 'paused' | 'blocked' | 'archived';

const STATE_FILTERS: Array<{ id: StateFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'blocked', label: 'Not dispatching' },
  { id: 'paused', label: 'Paused' },
  { id: 'archived', label: 'Archived' }
];

export const SCHEDULE_DAY_OPTIONS: SelectOption[] = [
  { value: '', label: 'No day selected' },
  { value: 'Mon', label: 'Monday' },
  { value: 'Tue', label: 'Tuesday' },
  { value: 'Wed', label: 'Wednesday' },
  { value: 'Thu', label: 'Thursday' },
  { value: 'Fri', label: 'Friday' },
  { value: 'Sat', label: 'Saturday' },
  { value: 'Sun', label: 'Sunday' }
];

function str(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function nested(item: DataItem | null | undefined, key: string): DataItem {
  const value = item?.[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as DataItem) : {};
}

function rowId(item: DataItem) {
  return str(item, ['id', 'policy_id']);
}

function optionLabel(options: SelectOption[], value: string) {
  return options.find((option) => option.value === value)?.label ?? value.replace(/_/g, ' ');
}

export function isValidTimezone(value: string) {
  if (!value.trim()) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value.trim() }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

export function browserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    return '';
  }
}

/** A recorded instant rendered in the schedule's own IANA timezone; never re-guessed. */
export function formatScheduleInstant(iso: string, timezone: string) {
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return { primary: 'Not recorded', viewer: '', zone: timezone || 'Not recorded' };
  const zone = isValidTimezone(timezone) ? timezone : 'UTC';
  const sameYear = new Date(at).getUTCFullYear() === new Date().getUTCFullYear();
  const options: Intl.DateTimeFormatOptions = { weekday: 'short', month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }), hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  const primary = new Intl.DateTimeFormat(undefined, { ...options, timeZone: zone }).format(new Date(at));
  const viewerZone = browserTimezone();
  const viewer = viewerZone && viewerZone !== zone
    ? `${new Intl.DateTimeFormat(undefined, { ...options, timeZone: viewerZone }).format(new Date(at))} your time (${viewerZone})`
    : '';
  return { primary, viewer, zone: isValidTimezone(timezone) ? timezone : 'UTC (schedule timezone not recorded)' };
}

export type ScheduleSafeWindow = { day: string; start: string; end: string; timezone: string };

export function scheduleSafeWindows(policy: DataItem): ScheduleSafeWindow[] {
  const windows = Array.isArray(policy.safe_windows) ? policy.safe_windows : [];
  return windows
    .filter((entry): entry is DataItem => Boolean(entry) && typeof entry === 'object' && !Array.isArray(entry))
    .map((entry) => ({
      day: str(entry, ['day']),
      start: str(entry, ['start']),
      end: str(entry, ['end']),
      timezone: str(entry, ['timezone'], str(policy, ['timezone']))
    }))
    .filter((entry) => entry.start || entry.end);
}

export function formatSafeWindowList(policy: DataItem) {
  const windows = scheduleSafeWindows(policy);
  if (windows.length === 0) return '';
  return windows.map((entry) => `${entry.day} ${entry.start}–${entry.end}${entry.timezone ? ` ${entry.timezone}` : ''}`.trim()).join(', ');
}

export function scheduleCheck(policy: DataItem, checks: DataItem[]) {
  const checkId = str(policy, ['check_id'], str(nested(policy, 'check'), ['check_id', 'id']));
  const catalog = checks.find((check) => str(check, ['check_id', 'id']) === checkId) ?? null;
  const embedded = nested(policy, 'check');
  return {
    checkId,
    record: catalog ?? (Object.keys(embedded).length ? embedded : null),
    inCatalog: Boolean(catalog),
    name: plainCheckName(str(catalog ?? embedded, ['name', 'title'], checkId || 'Check not recorded')) as string
  };
}

export function scheduleTarget(policy: DataItem) {
  const target = nested(policy, 'target');
  const group = nested(policy, 'target_group');
  const targetId = str(policy, ['target_id'], str(target, ['id']));
  const groupId = str(policy, ['target_group_id'], str(group, ['id']));
  return {
    targetId,
    targetLabel: str(target, ['value', 'hostname'], targetId),
    targetKind: str(target, ['kind']).replace(/_/g, ' '),
    groupId,
    groupLabel: str(group, ['name'], groupId)
  };
}

/** Name-first schedule label: the check it runs and the exact target it is bound to. */
export function scheduleDisplayName(policy: DataItem, checks: DataItem[]) {
  const explicit = str(policy, ['name', 'title']);
  if (explicit) return explicit;
  const { name } = scheduleCheck(policy, checks);
  const { targetLabel } = scheduleTarget(policy);
  return targetLabel ? `${name} on ${targetLabel}` : name;
}

export type ScheduleDispatch = {
  bucket: 'scheduled' | 'due' | 'blocked' | 'paused' | 'archived' | 'manual';
  label: string;
  reason: string;
  nextRunAt: string;
};

/**
 * Explain whether and when a schedule will dispatch, using only recorded fields. A missing
 * next_run_at is never projected from cadence: the server computes it, so absence is a blocker.
 */
export function describeScheduleDispatch(policy: DataItem, checks: DataItem[], now = Date.now()): ScheduleDispatch {
  const state = str(policy, ['state']);
  const cadence = str(policy, ['cadence']);
  const nextRunAt = str(policy, ['next_run_at']);
  const check = scheduleCheck(policy, checks);
  const target = scheduleTarget(policy);
  if (policy.archived_at || state === 'archived' || state === 'deleted') {
    return { bucket: 'archived', label: 'Archived', reason: 'Archived schedules never dispatch again.', nextRunAt: '' };
  }
  if (!state) {
    return { bucket: 'blocked', label: 'State not recorded', reason: 'The schedule record has no state, so dispatch cannot be confirmed.', nextRunAt: '' };
  }
  if (state === 'paused') {
    return { bucket: 'paused', label: 'Paused', reason: 'No dispatch happens until the schedule is resumed.', nextRunAt: '' };
  }
  if (state !== 'active') {
    const label = state.replace(/_/g, ' ');
    return { bucket: 'blocked', label: `${label.charAt(0).toUpperCase()}${label.slice(1)}`, reason: `The schedule state is ${label}, which does not dispatch.`, nextRunAt: '' };
  }
  if (policy.enabled === false) {
    return { bucket: 'blocked', label: 'Disabled', reason: 'The schedule is active but disabled, so the scheduler skips it.', nextRunAt: '' };
  }
  if (!target.targetId) {
    return { bucket: 'blocked', label: 'No exact target', reason: 'Legacy schedule without an exact target binding. Create a new schedule bound to one target.', nextRunAt: '' };
  }
  if (!check.checkId) {
    return { bucket: 'blocked', label: 'Check not recorded', reason: 'The schedule does not record which check it runs.', nextRunAt: '' };
  }
  if (checks.length > 0 && !check.inCatalog) {
    return { bucket: 'blocked', label: 'Check unavailable', reason: `Check ${check.checkId} is not in the current check catalog.`, nextRunAt: '' };
  }
  if (str(check.record, ['safety_class']) === 'soc_gated') {
    return { bucket: 'blocked', label: 'Not customer-runnable', reason: 'This check is SOC-governed and cannot dispatch from a customer schedule.', nextRunAt: '' };
  }
  if (cadence === 'manual') {
    return { bucket: 'manual', label: 'Manual only', reason: 'Manual cadence never dispatches automatically.', nextRunAt: '' };
  }
  if (!nextRunAt || !Number.isFinite(Date.parse(nextRunAt))) {
    return { bucket: 'blocked', label: 'Next run not recorded', reason: 'The scheduler has not recorded a next run for this active schedule. Edit timing or contact your administrator if it persists.', nextRunAt: '' };
  }
  if (Date.parse(nextRunAt) <= now) {
    return { bucket: 'due', label: 'Due', reason: 'The recorded run time has passed and is waiting for the dispatcher. Ownership, rate, and safe-window gates are rechecked at dispatch.', nextRunAt };
  }
  const windows = scheduleSafeWindows(policy);
  return {
    bucket: 'scheduled',
    label: 'Scheduled',
    reason: windows.length > 0
      ? 'Aligned to the configured safe window. Ownership and rate gates are rechecked at dispatch.'
      : 'Ownership and rate gates are rechecked at dispatch.',
    nextRunAt
  };
}

function filterBucket(dispatch: ScheduleDispatch): Exclude<StateFilter, 'all'> {
  if (dispatch.bucket === 'archived') return 'archived';
  if (dispatch.bucket === 'paused') return 'paused';
  if (dispatch.bucket === 'blocked' || dispatch.bucket === 'manual') return 'blocked';
  return 'active';
}

export function ScheduleStateBadge({ dispatch }: { dispatch: ScheduleDispatch }) {
  if (dispatch.bucket === 'paused') return <Badge tone="warn"><Pause size={12} aria-hidden="true" />Paused</Badge>;
  if (dispatch.bucket === 'archived') return <Badge tone="muted"><Archive size={12} aria-hidden="true" />Archived</Badge>;
  if (dispatch.bucket === 'blocked') return <Badge tone="warn"><CircleAlert size={12} aria-hidden="true" />{dispatch.label}</Badge>;
  if (dispatch.bucket === 'manual') return <Badge tone="muted"><CircleDashed size={12} aria-hidden="true" />Manual only</Badge>;
  if (dispatch.bucket === 'due') return <Badge tone="warn"><CalendarClock size={12} aria-hidden="true" />Due</Badge>;
  return <Badge tone="success"><CircleCheck size={12} aria-hidden="true" />Scheduled</Badge>;
}

/** Exact check link that carries the caller schedule (and target) so Back returns here. */
export function scheduleCheckHref(policy: DataItem, checks: DataItem[]) {
  const { checkId } = scheduleCheck(policy, checks);
  if (!checkId) return '';
  const { targetId } = scheduleTarget(policy);
  const policyId = rowId(policy);
  return `${buildDetailHref('check-detail', checkId)}${policyId ? `&policy=${encodeURIComponent(policyId)}` : ''}${targetId ? `&target=${encodeURIComponent(targetId)}` : ''}`;
}

export function ScheduleNextRun({ policy, checks }: { policy: DataItem; checks: DataItem[] }) {
  const dispatch = describeScheduleDispatch(policy, checks);
  const timezone = str(policy, ['timezone']);
  if (!dispatch.nextRunAt) {
    return (
      <span className="rf-cell-meta rf-next-blocked">
        <CircleDashed size={12} aria-hidden="true" />
        <span>{dispatch.bucket === 'archived' || dispatch.bucket === 'paused' || dispatch.bucket === 'manual' ? 'No next run' : 'Next run unavailable'}</span>
      </span>
    );
  }
  const instant = formatScheduleInstant(dispatch.nextRunAt, timezone);
  return (
    <span className="rf-cell-meta rf-next-run">
      <CalendarClock size={12} aria-hidden="true" />
      <span>
        <span className="rf-mono">{instant.primary}</span>
        <span className="rf-next-zone"> {instant.zone}</span>
        {instant.viewer ? <span className="rf-next-viewer">{instant.viewer}</span> : null}
      </span>
    </span>
  );
}

type SafeWindowDraft = { key: number; day: string; start: string; end: string };

function windowDraftsFrom(policy: DataItem): SafeWindowDraft[] {
  return scheduleSafeWindows(policy).map((entry, index) => ({ key: index + 1, day: entry.day, start: entry.start, end: entry.end }));
}

export function validateSafeWindowDrafts(drafts: Array<{ day: string; start: string; end: string }>) {
  for (const [index, entry] of drafts.entries()) {
    const label = `Safe window ${index + 1}`;
    if (!entry.day || !entry.start || !entry.end) return `${label}: choose a day, start, and end, or remove the window.`;
    if (entry.start >= entry.end) return `${label}: end time must be later than start time on the same day.`;
  }
  if (drafts.length > 14) return 'A schedule can have at most 14 safe windows.';
  return '';
}

/**
 * Edit only the mutable schedule fields the API accepts. The target, group, and check binding
 * is immutable and shown read-only; changing it means creating a new schedule.
 */
export function ScheduleEditDialog({
  policy,
  checks,
  config,
  session,
  open,
  onClose,
  onSaved
}: {
  policy: DataItem;
  checks: DataItem[];
  config: PortalConfig;
  session: Session;
  open: boolean;
  onClose: () => void;
  onSaved: (message: string) => void | Promise<void>;
}) {
  const id = rowId(policy);
  const initialCadence = str(policy, ['cadence'], 'manual');
  const initialVerdict = str(policy, ['expected_verdict'], 'pass');
  const initialTimezone = str(policy, ['timezone'], 'UTC');
  const initialWindowsKey = JSON.stringify(scheduleSafeWindows(policy).map(({ day, start, end }) => ({ day, start, end })));
  const [cadence, setCadence] = useState(initialCadence);
  const [verdict, setVerdict] = useState(initialVerdict);
  const [timezone, setTimezone] = useState(initialTimezone);
  const [windows, setWindows] = useState<SafeWindowDraft[]>(() => windowDraftsFrom(policy));
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const nextKey = useRef(100);
  const errorId = useId();
  const check = scheduleCheck(policy, checks);
  const target = scheduleTarget(policy);
  const viewerZone = browserTimezone();

  useEffect(() => {
    if (!open) return;
    setCadence(initialCadence);
    setVerdict(initialVerdict);
    setTimezone(initialTimezone);
    setWindows(windowDraftsFrom(policy));
    setError('');
    setConfirmDiscard(false);
    // Reset only when the dialog opens for this exact record revision.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, id, str(policy, ['schedule_revision', 'updated_at'])]);

  const windowPayload = windows.map(({ day, start, end }) => ({ day, start, end }));
  const changed: Record<string, unknown> = {};
  if (cadence !== initialCadence) changed.cadence = cadence;
  if (verdict !== initialVerdict) changed.expected_verdict = verdict;
  if (timezone.trim() !== initialTimezone) changed.timezone = timezone.trim();
  if (JSON.stringify(windowPayload) !== initialWindowsKey || ('timezone' in changed && windows.length > 0)) {
    changed.safe_windows = windowPayload.map((entry) => ({ ...entry, timezone: timezone.trim() }));
  }
  const dirty = Object.keys(changed).length > 0;

  function requestClose() {
    if (saving) return;
    if (dirty && !confirmDiscard) {
      setConfirmDiscard(true);
      return;
    }
    onClose();
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dirty) {
      setError('No changes to save.');
      return;
    }
    if (!isValidTimezone(timezone)) {
      setError(`"${timezone}" is not a recognised IANA timezone, for example Europe/London or America/New_York.`);
      return;
    }
    const windowError = validateSafeWindowDrafts(windows);
    if (windowError) {
      setError(windowError);
      return;
    }
    setSaving(true);
    setError('');
    try {
      const result = await requestJson(config, session, `/v1/test-policies/${encodeURIComponent(id)}`, { method: 'PATCH', body: changed }) as DataItem;
      const nextRunAt = str(result, ['next_run_at']);
      const nextLabel = nextRunAt
        ? `Next run recomputed by the scheduler: ${formatScheduleInstant(nextRunAt, str(result, ['timezone'], timezone)).primary} ${str(result, ['timezone'], timezone)}.`
        : 'The scheduler recorded no next run for the updated timing.';
      await onSaved(`Schedule updated. ${nextLabel}`);
      onClose();
    } catch (err) {
      setError(apiErrorMessage(err, 'Schedule update failed. Your changes are kept below.'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormModal
      open={open}
      title="Edit schedule"
      description={`${scheduleDisplayName(policy, checks)}. Timing and expectation can change; the bound target and check cannot.`}
      onClose={requestClose}
      wide
    >
      <form className="product-form rf-edit-form" onSubmit={(event) => void handleSubmit(event)} aria-busy={saving || undefined} noValidate>
        <dl className="rf-binding-facts full" aria-label="Immutable binding">
          <div><dt>Check</dt><dd>{check.name}<span className="rf-mono"> {check.checkId || 'not recorded'}</span></dd></div>
          <div><dt>Exact target</dt><dd>{target.targetLabel || 'Not recorded'}{target.targetKind ? <span className="rf-mono"> {target.targetKind}</span> : null}</dd></div>
          <div><dt>Target group</dt><dd>{target.groupLabel || 'Not recorded'}</dd></div>
        </dl>
        <p className="rf-help full"><Lock size={12} aria-hidden="true" /> The binding is immutable. To validate a different target or check, create a new schedule.</p>
        <Select label="Cadence" name="cadence" value={cadence} options={[
          { value: 'manual', label: 'Manual (never automatic)' },
          { value: 'daily', label: 'Daily' },
          { value: 'weekly', label: 'Weekly' },
          { value: 'monthly', label: 'Monthly' }
        ]} onChange={setCadence} disabled={saving} />
        <Select label="Expected verdict" name="expected_verdict" value={verdict} options={[
          { value: 'pass', label: 'Pass' },
          { value: 'warn', label: 'Warn' },
          { value: 'fail', label: 'Fail' },
          { value: 'manual_review', label: 'Manual review' }
        ]} onChange={setVerdict} disabled={saving} hint="A declaration compared with recorded evidence, not a result." />
        <label className="full">
          <span>Schedule timezone (IANA)</span>
          <input
            name="timezone"
            value={timezone}
            onChange={(event) => setTimezone(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={timezone && !isValidTimezone(timezone) ? true : undefined}
            aria-describedby={`${errorId}-tz`}
            disabled={saving}
          />
          <span className="muted small" id={`${errorId}-tz`}>
            Cadence and safe windows are evaluated in this timezone.
            {viewerZone && viewerZone !== timezone ? (
              <> <button type="button" className="rf-link-button" onClick={() => setTimezone(viewerZone)} disabled={saving}>Use {viewerZone}</button></>
            ) : null}
          </span>
        </label>
        <fieldset className="full rf-window-editor">
          <legend>Safe windows</legend>
          <p className="rf-help">Scheduled runs only start inside a window. No windows means any time.</p>
          {windows.length === 0 ? <p className="muted small">No safe window. Runs can start at any time on the cadence.</p> : null}
          <ul className="rf-window-list">
            {windows.map((entry, index) => (
              <li key={entry.key} className="rf-window-row">
                <Select
                  label={`Window ${index + 1} day`}
                  value={entry.day}
                  options={SCHEDULE_DAY_OPTIONS}
                  onChange={(day) => setWindows((current) => current.map((item) => item.key === entry.key ? { ...item, day } : item))}
                  disabled={saving}
                />
                <label>
                  <span>Start</span>
                  <input type="time" value={entry.start} onChange={(event) => setWindows((current) => current.map((item) => item.key === entry.key ? { ...item, start: event.target.value } : item))} disabled={saving} />
                </label>
                <label>
                  <span>End</span>
                  <input type="time" value={entry.end} onChange={(event) => setWindows((current) => current.map((item) => item.key === entry.key ? { ...item, end: event.target.value } : item))} disabled={saving} />
                </label>
                <Button type="button" size="sm" variant="ghost" disabled={saving} onClick={() => setWindows((current) => current.filter((item) => item.key !== entry.key))} aria-label={`Remove window ${index + 1}`}>Remove</Button>
              </li>
            ))}
          </ul>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            disabled={saving || windows.length >= 14}
            onClick={() => {
              nextKey.current += 1;
              setWindows((current) => [...current, { key: nextKey.current, day: '', start: '', end: '' }]);
            }}
          >
            Add safe window
          </Button>
        </fieldset>
        {error ? <div className="form-banner error full" role="alert" id={errorId}>{error}</div> : null}
        {confirmDiscard ? (
          <div className="form-banner neutral full rf-discard" role="alert">
            <span>Discard unsaved schedule changes?</span>
            <span className="row-actions">
              <Button type="button" size="sm" variant="secondary" onClick={() => setConfirmDiscard(false)}>Keep editing</Button>
              <Button type="button" size="sm" variant="danger" onClick={onClose}>Discard changes</Button>
            </span>
          </div>
        ) : null}
        <div className="form-actions full">
          <span className="muted small rf-dirty-note" aria-live="polite">{dirty ? `${Object.keys(changed).length} field${Object.keys(changed).length === 1 ? '' : 's'} changed` : 'No changes yet'}</span>
          <Button type="button" variant="ghost" disabled={saving} onClick={requestClose}>Cancel</Button>
          <Button type="submit" loading={saving} disabled={!dirty || saving}>Save schedule</Button>
        </div>
      </form>
    </FormModal>
  );
}

/**
 * Contextual Edit / Pause / Resume / Archive for one schedule. Only actions the API supports
 * for the current state are offered; every confirmation restates the exact binding.
 */
export function ScheduleActions({
  policy,
  checks,
  config,
  session,
  canWrite,
  onChanged,
  onError,
  compact = false
}: {
  policy: DataItem;
  checks: DataItem[];
  config: PortalConfig;
  session: Session;
  canWrite: boolean;
  onChanged: (message: string) => void | Promise<void>;
  onError: (message: string) => void;
  compact?: boolean;
}) {
  const { confirm } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const id = rowId(policy);
  const dispatch = describeScheduleDispatch(policy, checks);
  const name = scheduleDisplayName(policy, checks);
  const target = scheduleTarget(policy);
  const archived = dispatch.bucket === 'archived';
  const paused = dispatch.bucket === 'paused';
  const recordedState = str(policy, ['state']);
  const canTogglePause = recordedState === 'active' || recordedState === 'paused';
  if (!canWrite) return compact ? <span className="muted small">Read only</span> : null;
  if (archived) return compact ? <span className="muted small">Archived</span> : null;

  async function mutate(label: string, request: () => Promise<unknown>, success: string) {
    setBusy(label);
    try {
      await request();
      await onChanged(success);
    } catch (err) {
      onError(apiErrorMessage(err, 'Schedule action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function togglePause() {
    const pausing = !paused;
    const ok = await confirm({
      title: pausing ? 'Pause schedule' : 'Resume schedule',
      description: pausing
        ? `Pause "${name}"? No run is dispatched to ${target.targetLabel || 'its target'} while paused. The binding is unchanged and an audit entry is recorded.`
        : `Resume "${name}"? The scheduler computes the next run from its ${str(policy, ['cadence'], 'recorded')} cadence in ${str(policy, ['timezone'], 'UTC')}; safe windows can defer it.`,
      confirmLabel: pausing ? 'Pause schedule' : 'Resume schedule',
      confirmTone: pausing ? 'danger' : 'default'
    });
    if (!ok) return;
    await mutate(pausing ? 'pause' : 'resume', () => requestJson(config, session, `/v1/test-policies/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: { state: pausing ? 'paused' : 'active' }
    }), pausing ? `Paused "${name}".` : `Resumed "${name}".`);
  }

  async function archive() {
    const ok = await confirm({
      title: 'Archive schedule',
      description: `Archive "${name}"? It will never dispatch again and cannot be restored from the portal. Recorded runs, findings, and audit history remain.`,
      confirmLabel: 'Archive schedule',
      confirmTone: 'danger'
    });
    if (!ok) return;
    await mutate('archive', () => requestJson(config, session, `/v1/test-policies/${encodeURIComponent(id)}`, { method: 'DELETE' }), `Archived "${name}".`);
  }

  return (
    <div className="row-actions rf-schedule-actions" aria-busy={busy !== '' || undefined}>
      <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => setEditOpen(true)} aria-label={compact ? `Edit schedule ${name}` : undefined}>Edit</Button>
      {canTogglePause ? (
        <Button size="sm" variant="secondary" loading={busy === 'pause' || busy === 'resume'} disabled={busy !== ''} onClick={() => void togglePause()} aria-label={compact ? `${paused ? 'Resume' : 'Pause'} schedule ${name}` : undefined}>
          {paused ? 'Resume' : 'Pause'}
        </Button>
      ) : null}
      <Button size="sm" variant="danger" loading={busy === 'archive'} disabled={busy !== ''} onClick={() => void archive()} aria-label={compact ? `Archive schedule ${name}` : undefined}>Archive</Button>
      <ScheduleEditDialog
        policy={policy}
        checks={checks}
        config={config}
        session={session}
        open={editOpen}
        onClose={() => setEditOpen(false)}
        onSaved={onChanged}
      />
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: ReactNode; hint: ReactNode }) {
  return (
    <div className="rf-stat">
      <span className="rf-stat-label">{label}</span>
      <span className="rf-stat-value">{value}</span>
      <span className="rf-stat-hint">{hint}</span>
    </div>
  );
}

function FeedbackBanner({ message, error }: { message: string; error: string }) {
  if (!message && !error) return null;
  return (
    <div className={error ? 'form-banner error' : 'form-banner neutral'} role={error ? 'alert' : 'status'}>
      {error || message}
    </div>
  );
}

function TargetBindingRow({
  targetGroupId,
  form,
  busy
}: {
  targetGroupId: string;
  form: PolicyCreateFormModel;
  busy: string;
}) {
  const group = form.targetGroups.find((candidate) => str(candidate, ['id']) === targetGroupId);
  const groupName = str(group, ['name'], targetGroupId);
  const binding = form.bindings[targetGroupId];
  const targets = binding?.targets ?? [];
  const check = form.selectedCheck;
  const compatibleTargets = check ? targets.filter((target) => isPolicyTargetCompatible(check, target)) : [];
  const selectedTarget = compatibleTargets.find((target) => str(target, ['id']) === binding?.selectedTargetId);
  const supportedKinds = policySupportedTargetKinds(check);
  const checkName = str(check, ['name', 'check_id'], 'selected check');
  const noCompatibleTargets = Boolean(
    check && !binding?.loading && !binding?.error && targets.length > 0 && compatibleTargets.length === 0
  );
  const options: SelectOption[] = [
    {
      value: '',
      label: binding?.loading
        ? 'Loading active targets…'
        : targets.length === 0
          ? 'No active targets available'
          : noCompatibleTargets
            ? 'No compatible targets'
            : 'Select exact target'
    },
    ...compatibleTargets.map((target) => {
      const targetId = str(target, ['id']);
      return {
        value: targetId,
        label: str(target, ['value'], targetId),
        description: `${effectivePolicyTargetKind(target).replace(/_/g, ' ')} · ${targetId}`
      };
    })
  ];

  return (
    <li className="rf-binding" aria-busy={binding?.loading || undefined}>
      <Select
        label={`${groupName} exact target`}
        value={binding?.selectedTargetId ?? ''}
        options={options}
        disabled={!check || !binding || binding.loading || Boolean(binding.error) || compatibleTargets.length === 0 || busy !== ''}
        onChange={(targetId) => form.onSelectTarget(targetGroupId, targetId)}
      />
      {binding?.error ? (
        <div className="form-banner error rf-binding-error" role="alert">
          <span>{groupName}: {binding.error}</span>
          <Button type="button" size="sm" variant="secondary" disabled={busy !== ''} onClick={() => form.onRetryTargets(targetGroupId)}>
            Retry targets
          </Button>
        </div>
      ) : selectedTarget ? (
        <p className="rf-binding-note">
          <CircleCheck size={14} aria-hidden="true" />
          <span>
            Bound identity <strong className="rf-mono">{str(selectedTarget, ['value'], binding.selectedTargetId)}</strong>
            {' '}<span className="rf-mono">{binding.selectedTargetId}</span>
          </span>
        </p>
      ) : noCompatibleTargets ? (
        <p className="form-banner neutral" role="status">
          {groupName} has no exact target compatible with {checkName}. This check supports {supportedKinds.join(', ') || 'any declared target kind'}. Choose another check or target group.
        </p>
      ) : !binding?.loading && targets.length === 0 ? (
        <p className="form-banner error" role="alert">{groupName} has no active target to schedule.</p>
      ) : null}
    </li>
  );
}

function CreateSchedulePanel({
  form,
  busy,
  message,
  error,
  safeCheckCount,
  panelId
}: {
  form: PolicyCreateFormModel;
  busy: string;
  message: string;
  error: string;
  safeCheckCount: number;
  panelId: string;
}) {
  const headingId = useId();
  const statusId = useId();
  const checkSectionId = useId();
  const scopeSectionId = useId();
  const cadenceSectionId = useId();
  const reviewSectionId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [checkQuery, setCheckQuery] = useState('');
  const noGroups = form.targetGroups.length === 0;
  const noChecks = safeCheckCount === 0;
  const selectedCount = form.selectedGroupIds.length;
  const viewerZone = browserTimezone();
  const timezoneValid = isValidTimezone(form.timezone);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const query = checkQuery.trim().toLowerCase();
  const filteredCheckOptions = query
    ? form.checkOptions.filter((option) => !option.value || option.value === form.checkId || `${option.label} ${option.value}`.toLowerCase().includes(query))
    : form.checkOptions;
  const matchCount = filteredCheckOptions.filter((option) => option.value).length;

  const readiness = noGroups
    ? 'Declare an active target group before creating a schedule.'
    : noChecks
      ? 'No customer-runnable checks are available to schedule.'
      : !form.checkId
        ? 'Select a check to continue.'
        : selectedCount === 0
          ? 'Select at least one target group.'
          : !form.bindingsReady
            ? 'Select one exact active target for every selected group.'
            : !timezoneValid
              ? 'Enter a valid IANA timezone, for example Europe/London.'
              : `Ready to create ${selectedCount} ${selectedCount === 1 ? 'schedule' : 'schedules'}, one per target group.`;
  const submitDisabled = noGroups || noChecks || !form.checkId || !form.bindingsReady || !timezoneValid || busy !== '';
  const checkName = str(form.selectedCheck, ['name', 'check_id']);
  const reviewRows = form.selectedGroupIds.map((groupId) => {
    const group = form.targetGroups.find((candidate) => str(candidate, ['id']) === groupId);
    const binding = form.bindings[groupId];
    const target = binding?.targets.find((candidate) => str(candidate, ['id']) === binding.selectedTargetId);
    return { groupId, groupName: str(group, ['name'], groupId), targetLabel: str(target, ['value'], binding?.selectedTargetId ?? '') };
  });

  return (
    <section id={panelId} className="rf-panel rf-create" aria-labelledby={headingId}>
      <div className="rf-create-head">
        <div className="rf-create-heading">
          <h2 id={headingId} ref={headingRef} tabIndex={-1}>New validation schedule</h2>
          <p>
            Bind a customer-runnable check to one exact active target in each selected group. Groups are written one at a time, and failed bindings stay selected for retry.
          </p>
        </div>
        <Button type="button" size="sm" variant="ghost" disabled={busy !== ''} onClick={form.onClose}>Cancel</Button>
      </div>

      <form className="product-form rf-policy-form" onSubmit={form.onSubmit} aria-busy={busy === 'create-test-policy' || undefined}>
        <input type="hidden" name="check_id" value={form.checkId} />
        <input type="hidden" name="cadence" value={form.cadence} />
        <input type="hidden" name="expected_verdict" value={form.expectedVerdict} />
        <input type="hidden" name="timezone" value={form.timezone} />

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={checkSectionId}><span className="rf-step" aria-hidden="true">1</span>Check</h3>
            <p>Only customer-runnable checks can be scheduled. The check decides which target kinds can be bound.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={checkSectionId}>
            <label className="full">
              <span>Find a check</span>
              <input
                type="search"
                value={checkQuery}
                onChange={(event) => setCheckQuery(event.target.value)}
                placeholder="Name or check ID"
                autoComplete="off"
                disabled={noChecks}
                aria-describedby={`${checkSectionId}-matches`}
              />
              <span className="muted small" id={`${checkSectionId}-matches`} aria-live="polite">
                {query ? `${formatNumber(matchCount)} of ${formatNumber(safeCheckCount)} runnable checks match` : `${formatNumber(safeCheckCount)} runnable checks`}
              </span>
            </label>
            <Select
              label="Check"
              value={form.checkId}
              options={filteredCheckOptions}
              disabled={noChecks}
              onChange={form.onCheckChange}
            />
            <Select
              label="Expected verdict"
              value={form.expectedVerdict}
              options={form.verdictOptions}
              onChange={form.onExpectedVerdictChange}
            />
            <p className="rf-help full">
              The expected verdict is a declaration. It is compared against external probe evidence once a run records it.
              {form.checkId ? <> <a href={`${buildDetailHref('check-detail', form.checkId)}`}>Review this check</a>.</> : null}
              {noChecks ? <> <a href="#checks">Review the check catalog</a>.</> : null}
            </p>
          </fieldset>
        </div>

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={scopeSectionId}><span className="rf-step" aria-hidden="true">2</span>Scope</h3>
            <p>Choose declared target groups, then one exact target in each. Targets are never assigned automatically, and the bound identity cannot change after creation.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={scopeSectionId}>
            <div className="full">
              <TargetGroupPicker
                groups={form.targetGroups}
                selectedIds={form.selectedGroupIds}
                onChange={form.onTargetGroupsChange}
                disabled={noGroups || busy !== ''}
              />
            </div>
            {noGroups ? (
              <p className="rf-help full">
                No active target groups are declared. <a href="#targets">Declare a target</a> first.
              </p>
            ) : null}
            {selectedCount > 0 ? (
              <ul className="rf-binding-list full" aria-live="polite" aria-label="Exact target per group">
                {form.selectedGroupIds.map((targetGroupId) => (
                  <TargetBindingRow key={targetGroupId} targetGroupId={targetGroupId} form={form} busy={busy} />
                ))}
              </ul>
            ) : null}
          </fieldset>
        </div>

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={cadenceSectionId}><span className="rf-step" aria-hidden="true">3</span>Timing</h3>
            <p>How often the check runs, in which timezone, and optionally when runs may start.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={cadenceSectionId}>
            <Select
              label="Cadence"
              value={form.cadence}
              options={form.cadenceOptions}
              onChange={form.onCadenceChange}
            />
            <label>
              <span>Schedule timezone (IANA)</span>
              <input
                value={form.timezone}
                onChange={(event) => form.onTimezoneChange(event.target.value)}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={!timezoneValid || undefined}
                aria-describedby={`${cadenceSectionId}-tz`}
              />
              <span className="muted small" id={`${cadenceSectionId}-tz`}>
                {timezoneValid ? 'Cadence and windows are evaluated in this timezone.' : 'Not a recognised IANA timezone.'}
                {viewerZone && viewerZone !== form.timezone ? (
                  <> <button type="button" className="rf-link-button" onClick={() => form.onTimezoneChange(viewerZone)}>Use {viewerZone}</button></>
                ) : null}
              </span>
            </label>
            <details className="rf-disclosure full">
              <summary>Safe window (optional)</summary>
              <div className="rf-disclosure-body">
                <p className="rf-help full">Leave every field blank for no safe window, or complete day, start, and end. The window uses the schedule timezone.</p>
                <Select label="Safe window day" name="safe_window_day" value={form.windowDay} options={SCHEDULE_DAY_OPTIONS} onChange={form.onWindowDayChange} />
                <label>
                  <span>Window start</span>
                  <input name="safe_window_start" type="time" />
                </label>
                <label>
                  <span>Window end</span>
                  <input name="safe_window_end" type="time" />
                </label>
              </div>
            </details>
          </fieldset>
        </div>

        {form.checkId && selectedCount > 0 ? (
          <div className="rf-form-section rf-review" aria-labelledby={reviewSectionId}>
            <div className="rf-form-intro">
              <h3 id={reviewSectionId}><span className="rf-step" aria-hidden="true">4</span>Review</h3>
              <p>Exactly these records are written. The scheduler computes each first run after creation.</p>
            </div>
            <div className="rf-form-fields">
              <ul className="rf-review-list full" aria-label="Schedules to create">
                {reviewRows.map((row) => (
                  <li key={row.groupId}>
                    <strong>{plainCheckName(checkName || form.checkId)}</strong>
                    <span> on </span>
                    <strong className="rf-mono">{row.targetLabel || 'target not selected'}</strong>
                    <span className="muted"> in {row.groupName}</span>
                  </li>
                ))}
              </ul>
              <p className="rf-help full">
                {optionLabel(form.cadenceOptions, form.cadence)} cadence · {timezoneValid ? form.timezone : 'timezone invalid'} · expects {optionLabel(form.verdictOptions, form.expectedVerdict).toLowerCase()} · {formatNumber(selectedCount)} {selectedCount === 1 ? 'record' : 'records'}
              </p>
            </div>
          </div>
        ) : null}

        <FeedbackBanner message={message} error={error} />

        <div className="rf-form-footer">
          <p id={statusId} className="rf-readiness" aria-live="polite">
            {submitDisabled && busy === '' ? <CircleDashed size={14} aria-hidden="true" /> : <CircleCheck size={14} aria-hidden="true" />}
            <span>{readiness}</span>
          </p>
          <div className="form-actions">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={form.onClose}>Cancel</Button>
            <Button
              type="submit"
              loading={busy === 'create-test-policy'}
              disabled={submitDisabled}
              aria-describedby={statusId}
            >
              Create schedule
            </Button>
          </div>
        </div>
      </form>
    </section>
  );
}

function readStateFilter(): StateFilter {
  const value = getRouteParam('status');
  return STATE_FILTERS.some((option) => option.id === value) ? value as StateFilter : 'all';
}

export function PoliciesRefined(props: PoliciesRefinedProps) {
  const { data, busy, message, error, canWritePolicies, createForm, config, session } = props;
  const [stateFilter, setStateFilterState] = useState<StateFilter>(readStateFilter);
  const panelId = useId();
  const tableHeadingId = useId();
  const createButtonRef = useRef<HTMLButtonElement>(null);
  const policiesUnavailable = Boolean(data.loadErrors.testPolicies);
  const formOpen = canWritePolicies && createForm.open;
  const wasFormOpen = useRef(formOpen);
  const checks = data.checks;

  function setStateFilter(next: StateFilter) {
    setStateFilterState(next);
    replaceRouteParams({ status: next === 'all' ? null : next });
  }

  useEffect(() => {
    if (wasFormOpen.current && !formOpen) {
      window.requestAnimationFrame(() => createButtonRef.current?.focus());
    }
    wasFormOpen.current = formOpen;
  }, [formOpen]);

  const dispatchById = useMemo(() => {
    const map = new Map<string, ScheduleDispatch>();
    for (const policy of data.testPolicies) map.set(rowId(policy), describeScheduleDispatch(policy, checks));
    return map;
  }, [data.testPolicies, checks]);

  const counts = useMemo(() => {
    const result: Record<StateFilter, number> = { all: data.testPolicies.length, active: 0, paused: 0, blocked: 0, archived: 0 };
    for (const policy of data.testPolicies) {
      const dispatch = dispatchById.get(rowId(policy));
      if (dispatch) result[filterBucket(dispatch)] += 1;
    }
    return result;
  }, [data.testPolicies, dispatchById]);

  const nextScheduled = useMemo(() => {
    let best: { at: string; policy: DataItem } | null = null;
    for (const policy of data.testPolicies) {
      const dispatch = dispatchById.get(rowId(policy));
      if (!dispatch || dispatch.bucket !== 'scheduled') continue;
      if (!best || dispatch.nextRunAt.localeCompare(best.at) < 0) best = { at: dispatch.nextRunAt, policy };
    }
    return best;
  }, [data.testPolicies, dispatchById]);

  const visiblePolicies = stateFilter === 'all'
    ? data.testPolicies
    : data.testPolicies.filter((policy) => {
      const dispatch = dispatchById.get(rowId(policy));
      return dispatch ? filterBucket(dispatch) === stateFilter : false;
    });

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'schedule',
      label: 'Schedule',
      render: (item) => {
        const check = scheduleCheck(item, checks);
        const href = scheduleCheckHref(item, checks);
        return (
          <div className="rf-cell">
            {href ? (
              <a className="rf-cell-title rf-check-link" href={href}>{check.name}</a>
            ) : <span className="rf-cell-title">{check.name}</span>}
            {check.checkId ? <span className="rf-mono rf-cell-meta">{check.checkId}</span> : null}
            {str(item, ['expected_verdict']) ? (
              <span className="rf-cell-meta" title="Declared expectation, not observed evidence">
                Expects {optionLabel(createForm.verdictOptions, str(item, ['expected_verdict'])).toLowerCase()}
              </span>
            ) : null}
          </div>
        );
      }
    },
    {
      key: 'scope',
      label: 'Exact target',
      render: (item) => {
        const target = scheduleTarget(item);
        return (
          <div className="rf-cell">
            {target.targetId ? (
              <a className="rf-cell-title rf-target-link" href={buildDetailHref('target-detail', target.targetId)}>{target.targetLabel}</a>
            ) : <span className="rf-cell-title">No exact target</span>}
            {target.groupId ? (
              <span className="rf-cell-meta">in <a href={buildDetailHref('target-group-detail', target.groupId)}>{target.groupLabel}</a></span>
            ) : null}
          </div>
        );
      }
    },
    {
      key: 'timing',
      label: 'Timing',
      render: (item) => {
        const windows = formatSafeWindowList(item);
        return (
          <div className="rf-cell">
            <span className="rf-cell-title">{optionLabel(createForm.cadenceOptions, str(item, ['cadence'], 'manual'))}</span>
            <ScheduleNextRun policy={item} checks={checks} />
            <span className="rf-cell-meta">{windows ? <>Window <span className="rf-mono">{windows}</span></> : 'No safe window'}</span>
          </div>
        );
      }
    },
    {
      key: 'status',
      label: 'Dispatch',
      render: (item) => {
        const dispatch = dispatchById.get(rowId(item)) ?? describeScheduleDispatch(item, checks);
        return (
          <div className="rf-cell">
            <ScheduleStateBadge dispatch={dispatch} />
            <span className="rf-cell-meta rf-dispatch-reason">{dispatch.reason}</span>
          </div>
        );
      }
    },
    ...(canWritePolicies ? [{
      key: 'actions',
      label: 'Actions',
      render: (item: DataItem) => (
        <ScheduleActions
          policy={item}
          checks={checks}
          config={config}
          session={session}
          canWrite={canWritePolicies}
          compact
          onChanged={async (success) => {
            props.onActionResult(success, '');
            await props.onRefresh();
          }}
          onError={(failure) => props.onActionResult('', failure)}
        />
      )
    }] : [])
  ];

  const filterLabel = STATE_FILTERS.find((option) => option.id === stateFilter)?.label ?? 'All';
  const emptyState = stateFilter !== 'all' && data.testPolicies.length > 0 ? (
    <EmptyState
      icon={ListFilter}
      title={`No ${filterLabel.toLowerCase()} schedules.`}
      body="Choose another state to see the remaining schedules."
      actionLabel="Show all schedules"
      onAction={() => setStateFilter('all')}
    />
  ) : (
    <EmptyState
      icon={CalendarClock}
      title="No validation schedules yet."
      body="A schedule runs one customer-runnable check against one exact target on a cadence. Declare a target first, then create a schedule."
      actionLabel={canWritePolicies ? 'Create schedule' : undefined}
      onAction={canWritePolicies ? props.onCreateSchedule : undefined}
    />
  );

  const nextInstant = nextScheduled ? formatScheduleInstant(nextScheduled.at, str(nextScheduled.policy, ['timezone'])) : null;

  function openCreate() {
    if (formOpen) {
      document.getElementById(panelId)?.querySelector<HTMLElement>('h2')?.focus();
      return;
    }
    props.onCreateSchedule();
  }

  return (
    <div className="content refined rf-policies">
      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Declared scope, bounded checks</p>
          <h1>Validation schedules</h1>
          <p className="rf-header-description">
            When each check runs against its exact target, in which timezone, and why a schedule is or is not dispatching. Expected verdicts stay declarations until external probe evidence is recorded.
          </p>
        </div>
        <div className="rf-header-actions">
          {canWritePolicies ? (
            <Button
              ref={createButtonRef}
              variant="default"
              size="sm"
              disabled={busy !== ''}
              aria-expanded={formOpen}
              aria-controls={formOpen ? panelId : undefined}
              onClick={openCreate}
            >
              <Plus size={14} aria-hidden="true" />
              Create schedule
            </Button>
          ) : null}
        </div>
      </header>

      <section className="rf-summary-strip" aria-label="Schedule summary">
        <Stat
          label="Active"
          value={policiesUnavailable ? 'Unavailable' : formatNumber(counts.active)}
          hint={policiesUnavailable ? 'Schedule data unavailable' : 'Scheduled or due with a recorded next run'}
        />
        <Stat
          label="Not dispatching"
          value={policiesUnavailable ? 'Unavailable' : formatNumber(counts.blocked)}
          hint={counts.blocked > 0 ? 'Active but blocked or manual; see the reason per row' : 'No blocked schedules'}
        />
        <Stat
          label="Paused"
          value={policiesUnavailable ? 'Unavailable' : formatNumber(counts.paused)}
          hint={`${formatNumber(counts.archived)} archived`}
        />
        <Stat
          label="Next scheduled run"
          value={<span className="rf-stat-date">{policiesUnavailable ? 'Unavailable' : nextInstant ? nextInstant.primary : 'None recorded'}</span>}
          hint={nextInstant ? `${nextInstant.zone} · ${scheduleDisplayName(nextScheduled!.policy, checks)}` : 'No active schedule has a recorded next run'}
        />
      </section>

      {formOpen ? (
        <CreateSchedulePanel
          form={createForm}
          busy={busy}
          message={message}
          error={error}
          safeCheckCount={props.safeChecks.length}
          panelId={panelId}
        />
      ) : (
        <FeedbackBanner message={message} error={error} />
      )}

      <section className="rf-section" aria-labelledby={tableHeadingId}>
        <div className="rf-section-head">
          <div className="rf-section-copy">
            <h2 id={tableHeadingId}>Schedules</h2>
            <p>Select a row for the schedule detail. The check name opens that exact check.</p>
          </div>
          <div className="rf-toolbar">
            <div className="rf-segmented" role="group" aria-label="Filter schedules by dispatch state">
              {STATE_FILTERS.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  aria-pressed={stateFilter === option.id}
                  onClick={() => setStateFilter(option.id)}
                >
                  {option.label}
                  <span className="rf-segmented-count">{formatNumber(counts[option.id])}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="rf-panel rf-panel-flush rf-stack-table">
          <DataTable
            columns={columns}
            items={visiblePolicies}
            loadError={data.loadErrors.testPolicies}
            onRetry={() => void props.onRefresh()}
            getRowId={rowId}
            getRowProps={(item) => policyRowProps(item, checks)}
            empty={emptyState}
          />
        </div>
        <div className="rf-footnotes">
          <p className="rf-footnote">
            <ShieldCheck size={14} aria-hidden="true" />
            <span>A recorded next run is a plan, not a result. Ownership, rate, concurrency, and safe-window gates are rechecked when the dispatcher runs.</span>
          </p>
          {!canWritePolicies ? (
            <p className="rf-footnote">
              <Lock size={14} aria-hidden="true" />
              <span>Read only. Changing schedules requires the test_policy:write permission.</span>
            </p>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function policyRowProps(item: DataItem, checks: DataItem[]): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  const id = rowId(item);
  if (!id) return {};
  const href = buildDetailHref('policy-detail', id);
  const navigate = () => {
    const hashIndex = href.indexOf('#');
    window.location.hash = hashIndex >= 0 ? href.slice(hashIndex + 1) : href;
  };
  return {
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': `Open schedule ${scheduleDisplayName(item, checks)}`,
    onClick: (event) => {
      if ((event.target as HTMLElement).closest('a, button, input, select, textarea, [role="button"]')) return;
      navigate();
    },
    onKeyDown: (event) => {
      if (event.target !== event.currentTarget) return;
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      navigate();
    }
  };
}
